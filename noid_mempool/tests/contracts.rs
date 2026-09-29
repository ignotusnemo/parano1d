// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_chain::{consensus::params::V2_ACTIVATION_HEIGHT, state::ChainState, SlotValue};
use noid_core::Block128;
use noid_gkr::{wallet_authorization::prove_experimental_object_authorization, OwnerAuthWitness};
use noid_mempool::{
    AsyncMempool, ChainView, DecodedMempoolIntent, EvictReason, MempoolConfig, MempoolEvent,
    SubmitError,
};
use noid_poseidon2b::primitives::{derive_address, SpendSecret};
use noid_tx::{
    experimental_object::{applications, ObjectIntent, ObjectOpening, ObjectRules, PROGRAM_STEPS},
    PagedSpendIntent, TxInput, TxOutput, TxPage,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

fn test_config() -> MempoolConfig {
    use noid_chain::mempool::BlockSelectionBudget;
    MempoolConfig::default().with_v2_block_budgets([63, 206].map(|pages| BlockSelectionBudget {
        pages,
        live_inputs: 504,
        contract_calls: 63,
    }))
}

fn secret(n: u8) -> SpendSecret {
    SpendSecret::from_bytes([n; 32])
}
fn at(offset: u64) -> u64 {
    V2_ACTIVATION_HEIGHT.unwrap_or(10) + offset
}

fn opening() -> ObjectOpening {
    ObjectOpening {
        program: [[Block128(0); 2]; PROGRAM_STEPS],
        state: Block128(3),
        claim_authority: derive_address(&secret(2)),
        recovery_authority: derive_address(&secret(3)),
        deadline: at(10),
        // Deliberately identical recipients isolate the authority switch.
        claim_recipient: derive_address(&secret(4)),
        recovery_recipient: derive_address(&secret(4)),
        rules: ObjectRules {
            max_fee: 20_000,
            min_retained: 0,
            max_payout: 100_000,
            modes: 15,
        },
    }
}

fn input() -> TxInput {
    TxInput {
        slot_index: 1,
        amount: 1_000_000,
        creation_id: 7,
    }
}

fn view(opening: &ObjectOpening, tip: u64, creation_id: u64) -> ChainView {
    let mut state = ChainState::with_log_slots(8);
    state
        .state
        .set_slot(
            1,
            SlotValue::with_owner_fields(1_000_000, creation_id, opening.root().as_fields()),
        )
        .unwrap();
    let epoch = noid_chain::consensus::tx_epoch_anchor_height_for_child(tip + 1);
    let mut header = noid_chain::consensus::genesis_header();
    header.height = epoch;
    ChainView::new(tip, HashMap::from([(epoch, header)]), 1, state.state)
}

fn page(opening: &ObjectOpening, height: u64) -> TxPage {
    opening
        .build_call(
            input(),
            2,
            10_000,
            view(opening, height - 1, 7).user_epoch_anchor_id,
            height,
            false,
        )
        .unwrap()
}

fn payment(opening: &ObjectOpening, height: u64, amount: u64) -> TxPage {
    opening
        .build_payment(
            input(),
            2,
            10_000,
            view(opening, height - 1, 7).user_epoch_anchor_id,
            height,
            TxOutput {
                slot_index: 3,
                amount,
                owner: opening.recipient_at(height),
            },
        )
        .unwrap()
}

fn encoded(opening: &ObjectOpening, page: TxPage, height: u64, key: u8) -> Vec<u8> {
    let bundle = prove_experimental_object_authorization(
        &page,
        opening,
        height,
        OwnerAuthWitness::new(secret(key)),
    )
    .unwrap();
    ObjectIntent {
        opening: opening.clone(),
        spend: PagedSpendIntent::new(vec![page], bundle.to_bytes().unwrap()).unwrap(),
    }
    .to_bytes()
    .unwrap()
}

fn counted_pool(opening: &ObjectOpening, tip: u64) -> (AsyncMempool, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let work = counter.clone();
    let pool = AsyncMempool::new(view(opening, tip, 7), test_config())
        .with_authorization_verification_executor(Arc::new(move |task| {
            work.fetch_add(1, Ordering::SeqCst);
            task()
        }));
    (pool, counter)
}

#[tokio::test]
async fn scheduled_admission_relay_selection_and_backward_fork_reorg() {
    let object = opening();
    let activation = V2_ACTIVATION_HEIGHT.unwrap_or(10);
    let bytes = encoded(&object, page(&object, activation), activation, 2);
    let (pool, work) = counted_pool(&object, activation - 2);
    assert!(pool.submit_encoded(bytes.clone()).await.is_err());
    assert_eq!(work.load(Ordering::SeqCst), 0);
    pool.update_chain_view(view(&object, activation - 1, 7))
        .await;
    if V2_ACTIVATION_HEIGHT.is_none() {
        assert!(pool.submit_encoded(bytes).await.is_err());
        assert_eq!(work.load(Ordering::SeqCst), 0);
        return;
    }
    let mut events = pool.subscribe();
    let id = pool.submit_encoded(bytes.clone()).await.unwrap();
    let MempoolEvent::TxAdmitted {
        hash, intent_bytes, ..
    } = events.try_recv().unwrap()
    else {
        panic!("admission must reach relay")
    };
    assert_eq!(hash, id);
    assert_eq!(intent_bytes.as_ref(), bytes);
    let details = pool.get_entry_details(&id).await.unwrap();
    assert_eq!(details.metadata.tx_hash, id);
    assert_eq!(details.contract_opening, Some(object.to_bytes().unwrap()));
    let receiver = AsyncMempool::new(view(&object, activation - 1, 7), test_config());
    assert_eq!(
        receiver
            .submit_encoded(intent_bytes.to_vec())
            .await
            .unwrap(),
        id
    );
    let expected = ObjectIntent::from_bytes(&bytes).unwrap();
    let selection = receiver
        .select_for_v2_mining(
            noid_chain::mempool::BlockSelectionBudget {
                pages: 63,
                live_inputs: 504,
                contract_calls: 63,
            },
            None,
            activation,
            expected.spend.pages[0].body.epoch_anchor,
        )
        .await
        .unwrap();
    assert!(!selection.large_class);
    let selected = selection.entries;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].logical_txid, id);
    assert_eq!(selected[0].contract_opening.as_ref(), Some(&object));
    assert_eq!(
        selected[0].cached_authorization.as_ref(),
        Some(&expected.spend.authorization_bytes)
    );
    assert!(selection.pending_outputs.contains(&2));
    assert!(matches!(
        pool.submit_encoded(bytes.clone()).await,
        Err(SubmitError::AlreadyAdmitted(_))
    ));
    assert_eq!(work.load(Ordering::SeqCst), 1);
    pool.update_chain_view(view(&object, activation - 2, 7))
        .await;
    assert!(pool.is_empty().await);
    assert!(pool.get_entry_details(&id).await.is_none());
    assert!(pool.reserved_output_slots().await.is_empty());
    assert!(pool.submit_encoded(bytes.clone()).await.is_err());
    assert_eq!(work.load(Ordering::SeqCst), 1);
    pool.update_chain_view(view(&object, activation - 1, 7))
        .await;
    pool.submit_encoded(bytes).await.unwrap();
    assert_eq!(work.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn malformed_or_mismatched_envelopes_cannot_consume_authorization_work() {
    let object = opening();
    let height = at(1);
    let (pool, work) = counted_pool(&object, height - 1);
    let intent = ObjectIntent {
        opening: object.clone(),
        spend: PagedSpendIntent::new(vec![page(&object, height)], vec![1; 20]).unwrap(),
    };
    let bytes = intent.to_bytes().unwrap();
    let mut other = intent.clone();
    other.opening.state = Block128(99);
    for submitted in [Vec::new(), bytes[..8].to_vec(), other.to_bytes().unwrap()] {
        let decoded = DecodedMempoolIntent::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.logical_txid(), intent.spend.logical_txid());
        assert!(pool.submit_decoded(decoded, submitted).await.is_err());
    }
    assert!(pool
        .submit(intent.spend.clone(), intent.spend.to_bytes().unwrap())
        .await
        .is_err());
    for mutation in 0..3 {
        let mut invalid = intent.clone();
        match mutation {
            0 => invalid.opening.state = Block128(99),
            1 => invalid.spend.pages[0].body.outputs[0].owner.0[0] ^= 1,
            _ => invalid.spend.pages[0].body.inputs[0].creation_id -= 1,
        }
        assert!(pool
            .submit_encoded(invalid.to_bytes().unwrap())
            .await
            .is_err());
    }
    assert_eq!(work.load(Ordering::SeqCst), 0);
    assert!(pool.is_empty().await);
}

#[tokio::test]
async fn authorizations_remain_bound_to_the_current_controller_and_slot_incarnation() {
    if V2_ACTIVATION_HEIGHT.is_none() {
        return;
    }
    let object = opening();
    let (pool, work) = counted_pool(&object, at(9));
    assert!(matches!(
        pool.submit_encoded(encoded(&object, page(&object, at(9)), at(9), 2))
            .await,
        Err(SubmitError::InvalidProof(_))
    ));
    assert_eq!(work.load(Ordering::SeqCst), 1);
    let bytes = encoded(&object, page(&object, at(10)), at(10), 3);
    pool.submit_encoded(bytes.clone()).await.unwrap();
    pool.update_chain_view(view(&object, at(8), 7)).await;
    assert!(pool.is_empty().await);
    pool.submit_encoded(encoded(&object, page(&object, at(9)), at(9), 2))
        .await
        .unwrap();
    pool.update_chain_view(view(&object, at(8), 8)).await;
    assert!(pool.is_empty().await);
    assert!(pool.submit_encoded(bytes).await.is_err());
    assert_eq!(work.load(Ordering::SeqCst), 3);
}

async fn submit_while_height_changes(
    object: &ObjectOpening,
    page: TxPage,
    from: u64,
    to: u64,
    key: u8,
) -> Result<noid_poseidon2b::primitives::TxBodyHash, SubmitError> {
    let (started, signal) = tokio::sync::oneshot::channel();
    let started = Arc::new(std::sync::Mutex::new(Some(started)));
    let (release, wait) = std::sync::mpsc::channel();
    let wait = Arc::new(std::sync::Mutex::new(wait));
    let pool = AsyncMempool::new(view(object, from - 1, 7), test_config())
        .with_authorization_verification_executor(Arc::new(move |task| {
            started.lock().unwrap().take().unwrap().send(()).unwrap();
            wait.lock().unwrap().recv().unwrap();
            task()
        }));
    let bytes = encoded(object, page, from, key);
    let submitter = pool.clone();
    let task = tokio::spawn(async move { submitter.submit_encoded(bytes).await });
    signal.await.unwrap();
    pool.update_chain_view(view(object, to - 1, 7)).await;
    release.send(()).unwrap();
    let result = task.await.unwrap();
    assert_eq!(pool.is_empty().await, result.is_err());
    result
}

#[tokio::test]
async fn activation_and_authority_are_rechecked_after_real_proof_verification() {
    let Some(activation) = V2_ACTIVATION_HEIGHT else {
        return;
    };
    let object = opening();
    assert!(submit_while_height_changes(
        &object,
        page(&object, activation),
        activation,
        activation - 1,
        2
    )
    .await
    .is_err());
    assert!(matches!(
        submit_while_height_changes(&object, page(&object, at(9)), at(9), at(10), 2).await,
        Err(SubmitError::InvalidProof(_))
    ));
    assert!(
        submit_while_height_changes(&object, page(&object, at(8)), at(8), at(9), 2)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn recurring_successor_cannot_be_retargeted_after_authorization() {
    if V2_ACTIVATION_HEIGHT.is_none() {
        return;
    }
    let height = at(1);
    let object = applications::recurring_payment(
        derive_address(&secret(3)),
        derive_address(&secret(2)),
        applications::RecurringPayment {
            first_due_height: height,
            period_blocks: 10,
            payment: 30_000,
            recover_at: at(100),
            max_fee: 20_000,
        },
    )
    .unwrap();
    let call = payment(&object, height, 30_000);
    assert!(object.check_call(&call, height + 1).is_err());
    assert!(
        submit_while_height_changes(&object, call.clone(), height, height + 1, 2)
            .await
            .is_err()
    );
    let (pool, _) = counted_pool(&object, height - 1);
    pool.submit_encoded(encoded(&object, call, height, 2))
        .await
        .unwrap();
    let mut events = pool.subscribe();
    pool.on_new_block(&[], height, view(&object, height, 7))
        .await;
    assert!(pool.is_empty().await);
    assert!(matches!(
        events.try_recv(),
        Ok(MempoolEvent::TxEvicted {
            reason: EvictReason::ContractContextChanged,
            ..
        })
    ));
    let rebuilt = payment(&object, height + 1, 30_000);
    pool.submit_encoded(encoded(&object, rebuilt, height + 1, 2))
        .await
        .unwrap();
}

#[tokio::test]
async fn period_budget_keeps_stable_calls_but_evicts_at_window_reset() {
    if V2_ACTIVATION_HEIGHT.is_none() {
        return;
    }
    let height = at(1);
    let object = applications::period_budget_wallet(
        derive_address(&secret(2)),
        derive_address(&secret(3)),
        None,
        applications::PeriodBudget {
            start_height: height,
            period_blocks: 10,
            budget: 100_000,
            recover_at: at(100),
            max_fee: 20_000,
            max_payout: 50_000,
            min_retained: 20_000,
        },
    )
    .unwrap();
    let bytes = encoded(&object, payment(&object, height, 30_000), height, 2);
    let (pool, work) = counted_pool(&object, height - 1);
    pool.submit_encoded(bytes).await.unwrap();
    pool.update_chain_view(view(&object, height, 7)).await;
    assert_eq!(pool.len().await, 1);
    pool.update_chain_view(view(&object, height + 9, 7)).await;
    assert!(pool.is_empty().await);
    assert_eq!(
        work.load(Ordering::SeqCst),
        1,
        "tip changes must not rerun authorization proofs"
    );
    let reset = payment(&object, height + 10, 30_000);
    assert!(
        submit_while_height_changes(&object, reset, height + 10, height + 11, 2)
            .await
            .is_err()
    );
}
