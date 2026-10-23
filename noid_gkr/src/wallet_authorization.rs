// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production witness-hiding wallet authorization artifact.

use noid_core::Block128;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};
use noid_poseidon2b::primitives::SpendSecret;
use noid_tx::OwnerAuthorizationVersion;
use noid_tx::{
    canonical_owner_auth, canonical_paged_spend_auth, validate_public_tx_logic, PagedSpendError,
    PublicLogicError, TxBody, TxPage,
};
use zeroize::Zeroize;

use crate::{
    evaluate_permutation, owner_auth_public_from_statement,
    zk_auth_capsule::ZkAuthCapsuleStateTable,
    zk_authorization::{
        verify_zk_authorization, ZkAuthCapsuleOwnerStatement, ZkAuthorizationProof,
    },
    OwnerAuthPublicInputs, OwnerAuthStatementError,
};

pub const MAX_AUTHORIZATION_BUNDLE_BYTES: usize = noid_tx::MAX_TX_AUTHORIZATION_BYTES;
const AUTHORIZATION_BUNDLE_MAGIC: [u8; 8] = *b"NOIDWZK1";
const AUTHORIZATION_BUNDLE_HEADER_BYTES: usize = AUTHORIZATION_BUNDLE_MAGIC.len() + 4;
/// Absolute cap for the transitional live-input-count metadata. The exact
/// shape-specific count is derived from the canonical body at production
/// boundaries and will be pinned to the validity bitmap by ActionSurface C'.
pub const MAX_AUTHORIZATION_LIVE_INPUTS: u8 = noid_tx::TX_INPUTS as u8;

/// Wallet-local authority to prove one transaction owned by one address.
///
/// The public transaction carries no proving secret.  A wallet constructs this
/// value from its active derived secret and moves it directly into
/// [`prove_wallet_authorization`].  The inner secret is private, the type is
/// intentionally neither `Clone`, `Debug`, nor serializable, and all retained
/// bytes are zeroized when the value leaves scope.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OwnerAuthWitness {
    spend_secret: SpendSecret,
}

impl OwnerAuthWitness {
    #[inline]
    pub fn new(spend_secret: SpendSecret) -> Self {
        Self { spend_secret }
    }

    /// The only raw-secret access point.  It is module-private so callers can
    /// hand proving authority in, but cannot recover or retain the secret.
    #[inline]
    fn spend_secret(&self) -> &SpendSecret {
        &self.spend_secret
    }
}

#[derive(Debug, Clone)]
pub struct CanonicalAuthorizationStatement {
    pub tx_index: usize,
    pub tx_body_hash: [Block128; 2],
    /// Transitional metadata derived from the canonical body, never from
    /// proof-carried public data. C' pins it to the canonical validity bitmap.
    pub live_input_count: u8,
    pub public: OwnerAuthPublicInputs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedAuthorization {
    pub tx_index: usize,
    pub live_input_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedAuthorizationBatch {
    pub user_tx_count: usize,
    pub live_input_count_total: usize,
}

#[derive(Debug, Clone)]
pub struct WalletAuthorizationBundle {
    pub proof: ZkAuthorizationProof,
}

impl WalletAuthorizationBundle {
    pub fn to_bytes(&self) -> Result<Vec<u8>, AuthorizationEncodeError> {
        let proof = self
            .proof
            .to_bytes()
            .map_err(|error| AuthorizationEncodeError::Proof(error.to_string()))?;
        let proof_len =
            u32::try_from(proof.len()).map_err(|_| AuthorizationEncodeError::LengthOverflow)?;
        let total = AUTHORIZATION_BUNDLE_HEADER_BYTES
            .checked_add(proof.len())
            .ok_or(AuthorizationEncodeError::LengthOverflow)?;
        if total > MAX_AUTHORIZATION_BUNDLE_BYTES {
            return Err(AuthorizationEncodeError::TooLarge {
                actual: total,
                max: MAX_AUTHORIZATION_BUNDLE_BYTES,
            });
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&AUTHORIZATION_BUNDLE_MAGIC);
        bytes.extend_from_slice(&proof_len.to_le_bytes());
        bytes.extend_from_slice(&proof);
        Ok(bytes)
    }

    /// Canonical wire bytes of the bundled proof alone — the byte-exact
    /// identity used to recognize an already-verified authorization when
    /// the same proof reappears in a block sidecar.
    pub fn proof_wire_bytes(&self) -> Option<Vec<u8>> {
        authorization_proof_wire_bytes(&self.proof)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthorizationDecodeError> {
        if bytes.len() > MAX_AUTHORIZATION_BUNDLE_BYTES {
            return Err(AuthorizationDecodeError::TooLarge {
                actual: bytes.len(),
                max: MAX_AUTHORIZATION_BUNDLE_BYTES,
            });
        }
        if bytes.len() < AUTHORIZATION_BUNDLE_HEADER_BYTES {
            return Err(AuthorizationDecodeError::Truncated);
        }
        if bytes[..AUTHORIZATION_BUNDLE_MAGIC.len()] != AUTHORIZATION_BUNDLE_MAGIC {
            return Err(AuthorizationDecodeError::InvalidMagic);
        }
        let proof_len = u32::from_le_bytes(
            bytes[AUTHORIZATION_BUNDLE_MAGIC.len()..AUTHORIZATION_BUNDLE_HEADER_BYTES]
                .try_into()
                .expect("four authorization bundle length bytes"),
        ) as usize;
        if proof_len > crate::ZK_AUTHORIZATION_MAX_WIRE_BYTES {
            return Err(AuthorizationDecodeError::ProofTooLarge {
                actual: proof_len,
                max: crate::ZK_AUTHORIZATION_MAX_WIRE_BYTES,
            });
        }
        let expected = AUTHORIZATION_BUNDLE_HEADER_BYTES
            .checked_add(proof_len)
            .ok_or(AuthorizationDecodeError::LengthOverflow)?;
        if expected > bytes.len() {
            return Err(AuthorizationDecodeError::Truncated);
        }
        if expected != bytes.len() {
            return Err(AuthorizationDecodeError::TrailingBytes {
                remaining: bytes.len() - expected,
            });
        }
        ZkAuthorizationProof::from_bytes(&bytes[AUTHORIZATION_BUNDLE_HEADER_BYTES..])
            .map(|proof| Self { proof })
            .map_err(|error| AuthorizationDecodeError::Proof(error.to_string()))
    }

    pub fn byte_len(&self) -> Result<usize, AuthorizationEncodeError> {
        self.to_bytes().map(|bytes| bytes.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationEncodeError {
    TooLarge { actual: usize, max: usize },
    LengthOverflow,
    Proof(String),
}

impl std::fmt::Display for AuthorizationEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthorizationEncodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecodeError {
    TooLarge { actual: usize, max: usize },
    InvalidMagic,
    Truncated,
    ProofTooLarge { actual: usize, max: usize },
    LengthOverflow,
    TrailingBytes { remaining: usize },
    Proof(String),
}

impl std::fmt::Display for AuthorizationDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthorizationDecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveAuthorizationError {
    PublicLogic(PublicLogicError),
    PagedSpend(PagedSpendError),
    OwnerAuthStatement(String),
    /// The witness-hiding prover failed. Internal field values are
    /// deliberately not retained in the wallet/RPC-facing error.
    Proof,
    BoundaryMismatch {
        input_index: usize,
        field: &'static str,
    },
}

impl From<PublicLogicError> for ProveAuthorizationError {
    fn from(value: PublicLogicError) -> Self {
        Self::PublicLogic(value)
    }
}

impl From<PagedSpendError> for ProveAuthorizationError {
    fn from(value: PagedSpendError) -> Self {
        Self::PagedSpend(value)
    }
}

impl std::fmt::Display for ProveAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProveAuthorizationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyAuthorizationError {
    PublicLogic(PublicLogicError),
    PagedSpend(PagedSpendError),
    OwnerAuthStatement(String),
    AuthProof,
}

/// Fail-closed production statement boundary. Every consensus-facing
/// authorization statement uses the fixed one-owner layout. The live count is
/// transitional body-derived metadata until C' pins it to the body bitmap.
pub fn validate_authorization_statement(
    statement: &CanonicalAuthorizationStatement,
) -> Result<(), VerifyAuthorizationError> {
    if statement.public.layout != crate::OwnerAuthLayout::FIXED {
        return Err(VerifyAuthorizationError::OwnerAuthStatement(
            "production owner-auth statement must use the canonical one-owner layout".to_string(),
        ));
    }
    if !(1..=MAX_AUTHORIZATION_LIVE_INPUTS).contains(&statement.live_input_count) {
        return Err(VerifyAuthorizationError::OwnerAuthStatement(format!(
            "live input count {} is outside 1..={MAX_AUTHORIZATION_LIVE_INPUTS}",
            statement.live_input_count
        )));
    }
    if statement.public.tx_body_hash != statement.tx_body_hash {
        return Err(VerifyAuthorizationError::OwnerAuthStatement(
            "statement tx_body_hash does not match canonical owner-auth public input".to_string(),
        ));
    }
    Ok(())
}

impl From<PublicLogicError> for VerifyAuthorizationError {
    fn from(value: PublicLogicError) -> Self {
        Self::PublicLogic(value)
    }
}

impl From<PagedSpendError> for VerifyAuthorizationError {
    fn from(value: PagedSpendError) -> Self {
        Self::PagedSpend(value)
    }
}

impl std::fmt::Display for VerifyAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VerifyAuthorizationError {}

pub fn prove_wallet_authorization(
    body: &TxBody,
    witness: OwnerAuthWitness,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    prove_wallet_authorization_for_version(body, witness, OwnerAuthorizationVersion::V4)
}

pub fn prove_wallet_authorization_for_version(
    body: &TxBody,
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    validate_public_tx_logic(body)?;
    let canonical = canonical_owner_auth(body)
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let input_position = body
        .live_inputs()
        .next()
        .map(|(index, _)| index)
        .expect("canonical user transaction has a live input");
    let public =
        owner_auth_public_from_statement(&canonical).map_err(map_owner_auth_prove_error)?;
    prove_selected_authorization(public, input_position, witness, version)
}

/// Prove one unchanged witness-hiding capsule for a complete PagedSpend group.
pub fn prove_paged_spend_authorization(
    pages: &[TxPage],
    witness: OwnerAuthWitness,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    prove_paged_spend_authorization_for_version(pages, witness, OwnerAuthorizationVersion::V4)
}

pub fn prove_paged_spend_authorization_for_version(
    pages: &[TxPage],
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    let canonical = canonical_paged_spend_auth(pages)?;
    let input_position = pages
        .iter()
        .enumerate()
        .find_map(|(page, page_body)| {
            page_body
                .body
                .live_inputs()
                .next()
                .map(|(slot, _)| page * noid_tx::TX_INPUTS + slot)
        })
        .expect("canonical PagedSpend has a live input");
    let public = OwnerAuthPublicInputs::new(
        canonical.logical_txid.as_fields(),
        canonical.input_owner.as_fields(),
    );
    prove_selected_authorization(public, input_position, witness, version)
}

/// Research-v2 twin for an object contract. The logical transaction remains
/// bound exactly as in the wallet path, while the private owner permutation
/// proves the controller committed by the object opening rather than treating
/// the object's State root as a wallet address. HistoryStep is responsible for
/// binding that controller to the consumed object root.
#[doc(hidden)]
pub fn prove_v2_contract_controller_authorization(
    pages: &[TxPage],
    controller: [Block128; 2],
    witness: OwnerAuthWitness,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    prove_v2_contract_controller_authorization_for_version(
        pages,
        controller,
        witness,
        OwnerAuthorizationVersion::V4,
    )
}

pub fn prove_v2_contract_controller_authorization_for_version(
    pages: &[TxPage],
    controller: [Block128; 2],
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    let canonical = canonical_paged_spend_auth(pages)?;
    let input_position = pages
        .iter()
        .enumerate()
        .find_map(|(page, page_body)| {
            page_body
                .body
                .live_inputs()
                .next()
                .map(|(slot, _)| page * noid_tx::TX_INPUTS + slot)
        })
        .expect("canonical v2 contract call has a live input");
    let public = OwnerAuthPublicInputs::new(canonical.logical_txid.as_fields(), controller);
    prove_selected_authorization(public, input_position, witness, version)
}

fn prove_selected_authorization(
    public: OwnerAuthPublicInputs,
    input_position: usize,
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    // The selected capsule commits exactly the address-permutation state
    // table. Keep every secret-bearing temporary zeroizing and never expose a
    // reusable state/bank constructor at the wallet boundary.
    let iv = capacity_iv(TAG_ADDRFIX);
    let permutation = witness.spend_secret().with_exposed_prover_fields(|secret| {
        let mut permutation_input = [secret[0], secret[1], iv[0], iv[1]];
        let permutation = evaluate_permutation(permutation_input);
        permutation_input.zeroize();
        permutation
    });
    if permutation.final_state()[..2] != public.expected_address {
        return Err(ProveAuthorizationError::BoundaryMismatch {
            input_index: input_position,
            field: "owner_auth",
        });
    }
    let state = ZkAuthCapsuleStateTable::from_permutation_witness(&permutation)
        .map_err(|_| ProveAuthorizationError::Proof)?;
    let statement = selected_statement(&public);
    let proof = crate::zk_authorization::prove_zk_authorization_from_state_table_for_version(
        &state, statement, version,
    )
    .map_err(|_| ProveAuthorizationError::Proof)?;
    Ok(WalletAuthorizationBundle { proof })
}

/// Isolated v2 wallet path. Reject malformed programs and State effects before
/// doing capsule work; derive the address from the opened timed policy.
pub fn prove_experimental_object_authorization(
    page: &TxPage,
    opening: &noid_tx::experimental_object::ObjectOpening,
    height: u64,
    witness: OwnerAuthWitness,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    prove_experimental_object_authorization_for_version(
        page,
        opening,
        height,
        witness,
        OwnerAuthorizationVersion::V4,
    )
}

pub fn prove_experimental_object_authorization_for_version(
    page: &TxPage,
    opening: &noid_tx::experimental_object::ObjectOpening,
    height: u64,
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    let checked = opening
        .check_call(page, height)
        .map_err(|e| ProveAuthorizationError::OwnerAuthStatement(e.to_string()))?;
    prove_v2_contract_controller_authorization_for_version(
        std::slice::from_ref(page),
        checked.authority.as_fields(),
        witness,
        version,
    )
}

/// Authorize the native header and every page/opening binding with the same
/// active wallet secret used for NOID and contract calls.
pub fn prove_native_asset_authorization(
    intent: &noid_tx::native_assets::wire::NativeIntent,
    expected_chain: [u8; 32],
    height: u64,
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    if version != OwnerAuthorizationVersion::V4 {
        return Err(ProveAuthorizationError::OwnerAuthStatement(
            "native asset authorization requires v2.1".into(),
        ));
    }
    let facts = intent
        .checked(expected_chain, height)
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let public = owner_auth_public_from_statement(&facts.pages.canonical_auth())
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    prove_selected_authorization(public, noid_tx::TX_INPUTS, witness, version)
}

pub fn verify_native_asset_authorization(
    intent: &noid_tx::native_assets::wire::NativeIntent,
    expected_chain: [u8; 32],
    height: u64,
    bundle: &WalletAuthorizationBundle,
    version: OwnerAuthorizationVersion,
) -> Result<(), VerifyAuthorizationError> {
    if version != OwnerAuthorizationVersion::V4 {
        return Err(VerifyAuthorizationError::OwnerAuthStatement(
            "native asset authorization requires v2.1".into(),
        ));
    }
    let facts = intent
        .checked(expected_chain, height)
        .map_err(|error| VerifyAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let public = owner_auth_public_from_statement(&facts.pages.canonical_auth())
        .map_err(|error| VerifyAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    crate::zk_authorization::verify_zk_authorization_for_version(
        selected_statement(&public),
        &bundle.proof,
        version,
    )
    .map(|_| ())
    .map_err(|_| VerifyAuthorizationError::AuthProof)
}

pub fn prove_native_financial_authorization(
    intent: &noid_tx::native_assets::wire::NativeIntent,
    expected_chain: [u8; 32],
    round: noid_tx::native_assets::nft_market::NftRoundContext,
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    if version != OwnerAuthorizationVersion::V4 {
        return Err(ProveAuthorizationError::OwnerAuthStatement(
            "native financial authorization requires v2.1".into(),
        ));
    }
    let facts = intent
        .checked_financial_owner(expected_chain, round)
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let public = owner_auth_public_from_statement(&facts.pages.canonical_auth())
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    prove_selected_authorization(public, noid_tx::TX_INPUTS, witness, version)
}

pub fn verify_native_financial_authorization(
    intent: &noid_tx::native_assets::wire::NativeIntent,
    expected_chain: [u8; 32],
    round: noid_tx::native_assets::nft_market::NftRoundContext,
    bundle: &WalletAuthorizationBundle,
    version: OwnerAuthorizationVersion,
) -> Result<(), VerifyAuthorizationError> {
    if version != OwnerAuthorizationVersion::V4 {
        return Err(VerifyAuthorizationError::OwnerAuthStatement(
            "native financial authorization requires v2.1".into(),
        ));
    }
    let facts = intent
        .checked_financial_owner(expected_chain, round)
        .map_err(|error| VerifyAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let public = owner_auth_public_from_statement(&facts.pages.canonical_auth())
        .map_err(|error| VerifyAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    crate::zk_authorization::verify_zk_authorization_for_version(
        selected_statement(&public),
        &bundle.proof,
        version,
    )
    .map(|_| ())
    .map_err(|_| VerifyAuthorizationError::AuthProof)
}

pub fn prove_native_trade_authorization(
    intent: &noid_tx::native_assets::trade::TradeIntent,
    expected_chain: [u8; 32],
    epoch_anchor: [u8; 32],
    height: u64,
    witness: OwnerAuthWitness,
    version: OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    if version != OwnerAuthorizationVersion::V4 {
        return Err(ProveAuthorizationError::OwnerAuthStatement(
            "native trade authorization requires v2.1".into(),
        ));
    }
    intent
        .checked(expected_chain, epoch_anchor, height)
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let auth = intent
        .canonical_auth()
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let public = owner_auth_public_from_statement(&auth)
        .map_err(|error| ProveAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    prove_selected_authorization(public, noid_tx::TX_INPUTS, witness, version)
}

pub fn verify_native_trade_authorization(
    intent: &noid_tx::native_assets::trade::TradeIntent,
    expected_chain: [u8; 32],
    epoch_anchor: [u8; 32],
    height: u64,
    bundle: &WalletAuthorizationBundle,
    version: OwnerAuthorizationVersion,
) -> Result<(), VerifyAuthorizationError> {
    if version != OwnerAuthorizationVersion::V4 {
        return Err(VerifyAuthorizationError::OwnerAuthStatement(
            "native trade authorization requires v2.1".into(),
        ));
    }
    intent
        .checked(expected_chain, epoch_anchor, height)
        .map_err(|error| VerifyAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let auth = intent
        .canonical_auth()
        .map_err(|error| VerifyAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    let public = owner_auth_public_from_statement(&auth)
        .map_err(|error| VerifyAuthorizationError::OwnerAuthStatement(error.to_string()))?;
    crate::zk_authorization::verify_zk_authorization_for_version(
        selected_statement(&public),
        &bundle.proof,
        version,
    )
    .map(|_| ())
    .map_err(|_| VerifyAuthorizationError::AuthProof)
}

pub fn verify_experimental_object_authorization(
    page: &TxPage,
    opening: &noid_tx::experimental_object::ObjectOpening,
    height: u64,
    bundle: &WalletAuthorizationBundle,
) -> Result<(), VerifyAuthorizationError> {
    verify_experimental_object_authorization_for_version(
        page,
        opening,
        height,
        bundle,
        OwnerAuthorizationVersion::V4,
    )
}

pub fn verify_experimental_object_authorization_for_version(
    page: &TxPage,
    opening: &noid_tx::experimental_object::ObjectOpening,
    height: u64,
    bundle: &WalletAuthorizationBundle,
    version: OwnerAuthorizationVersion,
) -> Result<(), VerifyAuthorizationError> {
    let checked = opening
        .check_call(page, height)
        .map_err(|e| VerifyAuthorizationError::OwnerAuthStatement(e.to_string()))?;
    let canonical = canonical_paged_spend_auth(std::slice::from_ref(page))?;
    let public = OwnerAuthPublicInputs::new(
        canonical.logical_txid.as_fields(),
        checked.authority.as_fields(),
    );
    crate::zk_authorization::verify_zk_authorization_for_version(
        selected_statement(&public),
        &bundle.proof,
        version,
    )
    .map(|_| ())
    .map_err(|_| VerifyAuthorizationError::AuthProof)
}

pub fn verify_wallet_authorization(
    body: &TxBody,
    bundle: &WalletAuthorizationBundle,
) -> Result<(), VerifyAuthorizationError> {
    verify_wallet_authorization_proof(body, &bundle.proof)
}

pub fn verify_wallet_authorization_proof(
    body: &TxBody,
    proof: &ZkAuthorizationProof,
) -> Result<(), VerifyAuthorizationError> {
    validate_public_tx_logic(body)?;
    let canonical = canonical_owner_auth(body)
        .map_err(|e| VerifyAuthorizationError::OwnerAuthStatement(e.to_string()))?;
    let public = owner_auth_public_from_statement(&canonical)
        .map_err(|e| VerifyAuthorizationError::OwnerAuthStatement(e.to_string()))?;
    let statement = CanonicalAuthorizationStatement {
        tx_index: 0,
        tx_body_hash: public.tx_body_hash,
        live_input_count: u8::try_from(body.live_input_count())
            .expect("canonical transaction input capacity fits u8"),
        public,
    };
    verify_authorization_statement_proof(&statement, proof).map(|_| ())
}

/// Verify one unchanged capsule against the logical hash and owner of a
/// complete PagedSpend group.
pub fn verify_paged_spend_authorization(
    pages: &[TxPage],
    bundle: &WalletAuthorizationBundle,
) -> Result<(), VerifyAuthorizationError> {
    verify_paged_spend_authorization_for_version(pages, bundle, OwnerAuthorizationVersion::V4)
}

pub fn verify_paged_spend_authorization_for_version(
    pages: &[TxPage],
    bundle: &WalletAuthorizationBundle,
    version: OwnerAuthorizationVersion,
) -> Result<(), VerifyAuthorizationError> {
    verify_paged_spend_authorization_proof_for_version(pages, &bundle.proof, version)
}

pub fn verify_paged_spend_authorization_proof(
    pages: &[TxPage],
    proof: &ZkAuthorizationProof,
) -> Result<(), VerifyAuthorizationError> {
    verify_paged_spend_authorization_proof_for_version(pages, proof, OwnerAuthorizationVersion::V4)
}

pub fn verify_paged_spend_authorization_proof_for_version(
    pages: &[TxPage],
    proof: &ZkAuthorizationProof,
    version: OwnerAuthorizationVersion,
) -> Result<(), VerifyAuthorizationError> {
    let canonical = canonical_paged_spend_auth(pages)?;
    let public = OwnerAuthPublicInputs::new(
        canonical.logical_txid.as_fields(),
        canonical.input_owner.as_fields(),
    );
    crate::zk_authorization::verify_zk_authorization_for_version(
        selected_statement(&public),
        proof,
        version,
    )
    .map(|_| ())
    .map_err(|_| VerifyAuthorizationError::AuthProof)
}

pub fn canonical_authorization_statement_from_body(
    tx_index: usize,
    tx_body_hash: [Block128; 2],
    body: &TxBody,
) -> Result<CanonicalAuthorizationStatement, OwnerAuthStatementError> {
    let canonical = canonical_owner_auth(body)?;
    let live_input_count = body.live_input_count();
    if live_input_count == 0 || live_input_count > noid_tx::TX_INPUTS {
        return Err(OwnerAuthStatementError::LiveInputCountOutOfRange {
            actual: live_input_count,
            max: noid_tx::TX_INPUTS,
        });
    }
    let live_input_count = u8::try_from(live_input_count).map_err(|_| {
        OwnerAuthStatementError::LiveInputCountOutOfRange {
            actual: live_input_count,
            max: noid_tx::TX_INPUTS,
        }
    })?;
    let public = owner_auth_public_from_statement(&canonical)?;
    Ok(CanonicalAuthorizationStatement {
        tx_index,
        tx_body_hash,
        live_input_count,
        public,
    })
}

/// Canonical wire bytes of one owner-auth proof (the encoding block
/// sidecars use). Both sides of the verified-authorization fast path —
/// mempool admission and block acceptance — compare these bytes.
pub fn authorization_proof_wire_bytes(proof: &ZkAuthorizationProof) -> Option<Vec<u8>> {
    proof.to_bytes().ok()
}

pub fn verify_authorization_statement_proof(
    statement: &CanonicalAuthorizationStatement,
    proof: &ZkAuthorizationProof,
) -> Result<VerifiedAuthorization, VerifyAuthorizationError> {
    validate_authorization_statement(statement)?;
    verify_zk_authorization(selected_statement(&statement.public), proof)
        .map_err(|_| VerifyAuthorizationError::AuthProof)?;

    Ok(VerifiedAuthorization {
        tx_index: statement.tx_index,
        live_input_count: usize::from(statement.live_input_count),
    })
}

fn selected_statement(public: &OwnerAuthPublicInputs) -> ZkAuthCapsuleOwnerStatement {
    ZkAuthCapsuleOwnerStatement {
        tx_body_hash: public.tx_body_hash,
        address: public.expected_address,
    }
}

fn map_owner_auth_prove_error(err: OwnerAuthStatementError) -> ProveAuthorizationError {
    ProveAuthorizationError::OwnerAuthStatement(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_auth_public_from_body;
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::primitives::{derive_address, Address};
    use noid_tx::{
        output_bitmap_bit, TxInput, TxOutput, TxPage, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
        TX_INPUTS, TX_OUTPUTS,
    };

    fn mk_secret_bytes(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(31).wrapping_add(i as u8).wrapping_add(11);
        }
        bytes
    }

    fn mk_secret(seed: u8) -> SpendSecret {
        SpendSecret::from_bytes(mk_secret_bytes(seed))
    }

    fn standard_body_and_secret() -> (TxBody, [u8; 32]) {
        let secret_bytes = mk_secret_bytes(7);
        let secret = SpendSecret::from_bytes(secret_bytes);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 17,
            amount: 100,
            creation_id: 0,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 29,
            amount: 95,
            owner: Address([0xB0; 32]),
        };
        let body = TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 5,
            input_owner: derive_address(&secret),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        };
        (body, secret_bytes)
    }

    fn repeated_owner_body_and_secret() -> (TxBody, [u8; 32]) {
        let secret_bytes = mk_secret_bytes(17);
        let secret = SpendSecret::from_bytes(secret_bytes);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 17,
            amount: 60,
            creation_id: 0,
        };
        inputs[1] = TxInput {
            slot_index: 18,
            amount: 40,
            creation_id: 0,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 29,
            amount: 95,
            owner: Address([0xB0; 32]),
        };
        let body = TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 5,
            input_owner: derive_address(&secret),
            inputs,
            outputs,
            validity_bitmap: (1 << 0) | (1 << 1) | output_bitmap_bit(0),
            is_coinbase: false,
        };
        (body, secret_bytes)
    }

    fn prove_standard_fixture() -> (TxBody, [u8; 32], WalletAuthorizationBundle) {
        let (body, secret_bytes) = standard_body_and_secret();
        let witness = OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes));
        let bundle =
            prove_wallet_authorization(&body, witness).expect("prove standard authorization");
        verify_wallet_authorization(&body, &bundle).expect("verify standard authorization");
        (body, secret_bytes, bundle)
    }

    #[test]
    fn object_capsule_binds_the_opened_authority_and_deadline_branch() {
        use noid_tx::experimental_object::{ObjectOpening, ObjectRules, PROGRAM_STEPS};
        let claim = mk_secret_bytes(41);
        let recovery = mk_secret_bytes(42);
        let opening = ObjectOpening {
            program: [[Block128(0); 2]; PROGRAM_STEPS],
            state: Block128(19),
            claim_authority: derive_address(&SpendSecret::from_bytes(claim)),
            recovery_authority: derive_address(&SpendSecret::from_bytes(recovery)),
            deadline: 10,
            claim_recipient: Address([3; 32]),
            recovery_recipient: Address([4; 32]),
            rules: ObjectRules {
                max_fee: 10,
                min_retained: 0,
                max_payout: 0,
                modes: 15,
            },
        };
        let page = opening
            .build_call(
                TxInput {
                    slot_index: 1,
                    amount: 100,
                    creation_id: 1,
                },
                2,
                5,
                [7; 32],
                9,
                false,
            )
            .unwrap();
        // The continuing body is valid on either side. Only the authorized
        // branch changes, so this tests the capsule binding itself.
        assert!(opening.check_call(&page, 10).is_ok());
        let before = prove_experimental_object_authorization(
            &page,
            &opening,
            9,
            OwnerAuthWitness::new(SpendSecret::from_bytes(claim)),
        )
        .unwrap();
        verify_experimental_object_authorization(&page, &opening, 9, &before).unwrap();
        assert!(verify_experimental_object_authorization(&page, &opening, 10, &before).is_err());
        assert!(verify_paged_spend_authorization(std::slice::from_ref(&page), &before).is_err());
        let after = prove_experimental_object_authorization(
            &page,
            &opening,
            10,
            OwnerAuthWitness::new(SpendSecret::from_bytes(recovery)),
        )
        .unwrap();
        verify_experimental_object_authorization(&page, &opening, 10, &after).unwrap();
        assert!(verify_experimental_object_authorization(&page, &opening, 9, &after).is_err());
        let mut changed = page.clone();
        changed.body.epoch_anchor[0] ^= 1;
        assert!(opening.check_call(&changed, 9).is_ok());
        assert!(verify_experimental_object_authorization(&changed, &opening, 9, &before).is_err());
        assert!(prove_experimental_object_authorization(
            &page,
            &opening,
            9,
            OwnerAuthWitness::new(SpendSecret::from_bytes(recovery)),
        )
        .is_err());
    }

    fn paged_fixture(statement_salt: u8) -> (Vec<TxPage>, [u8; 32]) {
        let (mut body, secret_bytes) = standard_body_and_secret();
        body.epoch_anchor[0] ^= statement_salt;
        body.inputs[0].slot_index += u32::from(statement_salt);
        body.inputs[0].creation_id += u64::from(statement_salt);
        body.outputs[0].slot_index += u32::from(statement_salt);
        body.validity_bitmap |= PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT;
        (vec![TxPage::new(body).unwrap()], secret_bytes)
    }

    #[test]
    fn paged_spend_reuses_the_capsule_but_not_the_statement_or_randomness() {
        let (first_pages, secret_bytes) = paged_fixture(3);
        let (second_pages, _) = paged_fixture(4);
        let first = prove_paged_spend_authorization(
            &first_pages,
            OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes)),
        )
        .expect("first PagedSpend capsule");
        let second = prove_paged_spend_authorization(
            &second_pages,
            OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes)),
        )
        .expect("second PagedSpend capsule");

        verify_paged_spend_authorization(&first_pages, &first).unwrap();
        verify_paged_spend_authorization(&second_pages, &second).unwrap();
        assert_ne!(first.to_bytes().unwrap(), second.to_bytes().unwrap());
        assert!(matches!(
            verify_paged_spend_authorization(&first_pages, &second),
            Err(VerifyAuthorizationError::AuthProof)
        ));
        assert!(matches!(
            verify_paged_spend_authorization(&second_pages, &first),
            Err(VerifyAuthorizationError::AuthProof)
        ));
    }

    #[test]
    fn strict_decoder_rejects_trailing_bytes_and_unknown_discriminant() {
        let (_, _, bundle) = prove_standard_fixture();
        let mut bytes = bundle.to_bytes().expect("serialize authorization");
        assert_eq!(
            bytes.len(),
            AUTHORIZATION_BUNDLE_HEADER_BYTES + bundle.proof.to_bytes().unwrap().len()
        );

        let mut oversized = bytes.clone();
        oversized[AUTHORIZATION_BUNDLE_MAGIC.len()..AUTHORIZATION_BUNDLE_HEADER_BYTES]
            .copy_from_slice(&((crate::ZK_AUTHORIZATION_MAX_WIRE_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes(&oversized),
            Err(AuthorizationDecodeError::ProofTooLarge { .. })
        ));

        bytes.push(0);
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes(&bytes),
            Err(AuthorizationDecodeError::TrailingBytes { remaining: 1 })
        ));

        let unknown_payload = [9u8, 0, 0, 0];
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes(&unknown_payload),
            Err(AuthorizationDecodeError::Truncated)
        ));

        // A pinned pre-hard-cut envelope prefix. Decoder rejection must not
        // depend on retaining or running the retired owner-auth prover.
        const RETIRED_OWNER_AUTH_FIXTURE: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes(RETIRED_OWNER_AUTH_FIXTURE),
            Err(AuthorizationDecodeError::InvalidMagic)
        ));
    }

    #[test]
    fn proof_and_body_tamper_reject() {
        let (mut body, _, mut bundle) = prove_standard_fixture();

        bundle.proof.owner.mask_mu += noid_core::Block256::ONE;
        assert!(matches!(
            verify_wallet_authorization(&body, &bundle),
            Err(VerifyAuthorizationError::AuthProof)
        ));

        let (_, _, honest_bundle) = prove_standard_fixture();
        body.input_owner = Address([0x44; 32]);
        assert!(matches!(
            verify_wallet_authorization(&body, &honest_bundle),
            Err(VerifyAuthorizationError::AuthProof)
                | Err(VerifyAuthorizationError::OwnerAuthStatement(_))
        ));
    }

    #[test]
    fn wrong_secret_rejects_before_proving() {
        let (mut body, secret_bytes) = standard_body_and_secret();

        assert!(matches!(
            prove_wallet_authorization(&body, OwnerAuthWitness::new(mk_secret(8))),
            Err(ProveAuthorizationError::BoundaryMismatch {
                input_index: 0,
                field: "owner_auth",
            })
        ));

        body.input_owner = Address([0x55; 32]);
        assert!(matches!(
            prove_wallet_authorization(
                &body,
                OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes)),
            ),
            Err(ProveAuthorizationError::BoundaryMismatch {
                input_index: 0,
                field: "owner_auth",
            })
        ));
    }

    #[test]
    fn repeated_inputs_use_fixed_owner_layout() {
        let (body, secret_bytes) = repeated_owner_body_and_secret();
        let bundle = prove_wallet_authorization(
            &body,
            OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes)),
        )
        .expect("prove repeated-owner authorization");
        verify_wallet_authorization(&body, &bundle).expect("verify repeated-owner authorization");

        let public = owner_auth_public_from_body(&body).expect("public owner auth");
        assert_eq!(public.layout, crate::OwnerAuthLayout::FIXED);
        let statement =
            canonical_authorization_statement_from_body(0, public.tx_body_hash, &body).unwrap();
        assert_eq!(statement.live_input_count, 2);
    }

    #[test]
    fn owner_auth_witness_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<OwnerAuthWitness>();
        static_assertions::assert_not_impl_any!(
            OwnerAuthWitness: Copy,
            Clone,
            std::fmt::Debug,
            serde::Serialize,
            serde::de::DeserializeOwned
        );
        fn assert_zeroize<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>() {}
        assert_zeroize::<OwnerAuthWitness>();
    }

    #[test]
    fn statement_verifier_rejects_split_tx_body_hash() {
        let (body, _, bundle) = prove_standard_fixture();
        let public = owner_auth_public_from_body(&body).expect("public owner auth");
        let mut statement =
            canonical_authorization_statement_from_body(3, public.tx_body_hash, &body)
                .expect("canonical authorization statement");
        statement.tx_body_hash[0] += Block128::ONE;

        assert!(matches!(
            verify_authorization_statement_proof(&statement, &bundle.proof),
            Err(VerifyAuthorizationError::OwnerAuthStatement(_))
        ));
    }

    #[test]
    fn production_statement_rejects_live_count_outside_transitional_cap() {
        let (body, _, bundle) = prove_standard_fixture();
        let public = owner_auth_public_from_body(&body).expect("public owner auth");
        let statement = canonical_authorization_statement_from_body(0, public.tx_body_hash, &body)
            .expect("canonical authorization statement");

        for bad_count in [0, MAX_AUTHORIZATION_LIVE_INPUTS + 1] {
            let mut bad = statement.clone();
            bad.live_input_count = bad_count;
            assert!(matches!(
                verify_authorization_statement_proof(&bad, &bundle.proof),
                Err(VerifyAuthorizationError::OwnerAuthStatement(_))
            ));
        }
    }

    #[test]
    fn spend_secret_bytes_are_absent_from_serialization() {
        let (_, secret_bytes, bundle) = prove_standard_fixture();
        let bytes = bundle.to_bytes().expect("serialize authorization");
        assert!(
            !bytes
                .windows(secret_bytes.len())
                .any(|window| window == secret_bytes),
            "raw spend secret must not be serialized in wallet authorization"
        );
    }

    #[test]
    fn wallet_facing_prover_errors_do_not_embed_secret_or_field_state() {
        let (mut body, secret_bytes) = standard_body_and_secret();
        body.input_owner = Address([0x55; 32]);
        let error = prove_wallet_authorization(
            &body,
            OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes)),
        )
        .expect_err("changed owner must reject before proving");
        let rendered = error.to_string();
        assert!(!rendered.contains(&hex::encode(secret_bytes)));
        assert!(!rendered.contains("Block128"));
    }
}
