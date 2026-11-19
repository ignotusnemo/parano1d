// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_chain::consensus::params::owner_authorization_version_with_hash_update;
use noid_chain::fri_state::{SlotValue, STATE_LOG_SLOTS};
use noid_chain::{apply_tx_at, ApplyError, ChainState};
use noid_gkr::wallet_authorization::{
    prove_experimental_object_authorization_for_version, prove_wallet_authorization_for_version,
    verify_experimental_object_authorization_for_version, verify_wallet_authorization,
    OwnerAuthWitness, WalletAuthorizationBundle,
};
use noid_poseidon2b::primitives::{derive_address, SpendSecret};
use noid_tx::experimental_object::{applications::timelocked_vault, ObjectError, ObjectOpening};
use noid_tx::{
    output_bitmap_bit, OwnerAuthorizationVersion, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
};

const CREATE_HEIGHT: u64 = 39;
const FORK_HEIGHT: u64 = 40;
const UNLOCK_HEIGHT: u64 = 50;
const INITIAL_AMOUNT: u64 = 10_000_000;
const FEE: u64 = 9_000;

fn version(height: u64) -> OwnerAuthorizationVersion {
    let explicit =
        owner_authorization_version_with_hash_update(height, Some(24), Some(FORK_HEIGHT));
    if noid_chain::consensus::params::PROOF_HASH_ACTIVATION_HEIGHT == Some(FORK_HEIGHT) {
        let selected = noid_chain::consensus::params::owner_authorization_version(height);
        assert_eq!(selected, explicit);
        selected
    } else {
        explicit
    }
}

#[test]
fn timelock_created_before_hash_update_withdraws_after_unlock_with_same_secret() {
    // Deterministic synthetic funds and secret. No wallet files or network access.
    let secret_bytes = [0x6d; 32];
    let owner = derive_address(&SpendSecret::from_bytes(secret_bytes));
    let contract = timelocked_vault(owner, UNLOCK_HEIGHT, FEE);
    let saved_opening = contract.to_bytes().unwrap();
    let saved_root = contract.root();
    let mut state = ChainState::from_sparse_utxos(
        STATE_LOG_SLOTS,
        &[(
            1,
            SlotValue::with_owner_fields(INITIAL_AMOUNT, 7, owner.as_fields()),
        )],
        7,
    )
    .unwrap();

    assert_eq!(version(CREATE_HEIGHT), OwnerAuthorizationVersion::V4);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    inputs[0] = TxInput {
        slot_index: 1,
        amount: INITIAL_AMOUNT,
        creation_id: 7,
    };
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    outputs[0] = contract.funding_output(2, INITIAL_AMOUNT - FEE).unwrap();
    let funding = TxBody {
        epoch_anchor: [0x31; 32],
        fee: FEE,
        input_owner: owner,
        inputs,
        outputs,
        validity_bitmap: 1 | output_bitmap_bit(0),
        is_coinbase: false,
    };
    let authorization = prove_wallet_authorization_for_version(
        &funding,
        OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes)),
        version(CREATE_HEIGHT),
    )
    .unwrap();
    verify_wallet_authorization(&funding, &authorization).unwrap();
    apply_tx_at(&mut state, &funding, CREATE_HEIGHT).unwrap();
    let locked_slot = state.state.slot(2);
    let locked_state_root = state.state_root();
    assert_eq!(
        [locked_slot.owner_hi, locked_slot.owner_lo],
        saved_root.as_fields()
    );
    assert_eq!(locked_slot.amount(), INITIAL_AMOUNT - FEE);
    assert_eq!(state.state.slot(1), SlotValue::EMPTY);

    // Read the same retained opening after the profile boundary.
    assert_eq!(version(FORK_HEIGHT - 1), OwnerAuthorizationVersion::V4);
    assert_eq!(version(FORK_HEIGHT), OwnerAuthorizationVersion::V5);
    let contract = ObjectOpening::from_bytes(&saved_opening).unwrap();
    assert_eq!(contract.root(), saved_root);
    assert_eq!(contract.recovery_authority, owner);
    assert_eq!(
        derive_address(&SpendSecret::from_bytes(secret_bytes)),
        owner
    );
    let input = TxInput {
        slot_index: 2,
        amount: locked_slot.amount(),
        creation_id: locked_slot.creation_id(),
    };
    for height in [
        CREATE_HEIGHT,
        FORK_HEIGHT - 1,
        FORK_HEIGHT,
        UNLOCK_HEIGHT - 1,
    ] {
        for terminal in [false, true] {
            assert_eq!(
                contract.build_call(input, 3, FEE, [0x31; 32], height, terminal),
                Err(ObjectError::Policy),
                "withdrawal must remain locked at height {height}",
            );
        }
    }
    assert_eq!(state.state_root(), locked_state_root);
    assert_eq!(state.state.slot(2), locked_slot);

    let withdrawal = contract
        .build_call(input, 3, FEE, [0x31; 32], UNLOCK_HEIGHT, true)
        .unwrap();
    let authorization = prove_experimental_object_authorization_for_version(
        &withdrawal,
        &contract,
        UNLOCK_HEIGHT,
        OwnerAuthWitness::new(SpendSecret::from_bytes(secret_bytes)),
        version(UNLOCK_HEIGHT),
    )
    .unwrap();
    let wire = authorization.to_bytes().unwrap();
    let authorization = WalletAuthorizationBundle::from_bytes(&wire).unwrap();
    verify_experimental_object_authorization_for_version(
        &withdrawal,
        &contract,
        UNLOCK_HEIGHT,
        &authorization,
        version(UNLOCK_HEIGHT),
    )
    .unwrap();
    assert!(verify_experimental_object_authorization_for_version(
        &withdrawal,
        &contract,
        UNLOCK_HEIGHT - 1,
        &authorization,
        version(UNLOCK_HEIGHT - 1),
    )
    .is_err());
    assert!(verify_experimental_object_authorization_for_version(
        &withdrawal,
        &contract,
        UNLOCK_HEIGHT,
        &authorization,
        version(CREATE_HEIGHT),
    )
    .is_err());
    assert!(prove_experimental_object_authorization_for_version(
        &withdrawal,
        &contract,
        UNLOCK_HEIGHT,
        OwnerAuthWitness::new(SpendSecret::from_bytes([0x72; 32])),
        version(UNLOCK_HEIGHT),
    )
    .is_err());

    apply_tx_at(&mut state, &withdrawal.body, UNLOCK_HEIGHT).unwrap();
    assert_eq!(state.state.slot(2), SlotValue::EMPTY);
    let returned = state.state.slot(3);
    assert_eq!([returned.owner_hi, returned.owner_lo], owner.as_fields());
    assert_eq!(returned.amount(), INITIAL_AMOUNT - 2 * FEE);
    assert_eq!(
        state.circulating_supply_micronoid,
        u128::from(returned.amount())
    );
    let after_withdrawal = state.state_root();
    assert_eq!(
        apply_tx_at(&mut state, &withdrawal.body, UNLOCK_HEIGHT + 1),
        Err(ApplyError::UnknownOrSpentInput),
    );
    assert_eq!(state.state_root(), after_withdrawal);
    println!(
        "timelock: created={CREATE_HEIGHT} fork={FORK_HEIGHT} unlock={UNLOCK_HEIGHT} \
         profile=V4->V5 returned={} micronoid same_owner=true early=rejected replay=rejected",
        returned.amount(),
    );
}
