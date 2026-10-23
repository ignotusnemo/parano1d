// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::config::test_config;
use noid_chain::mempool::BlockSelectionBudget;
use noid_chain::{consensus::params::V2_ACTIVATION_HEIGHT, state::ChainState};
use noid_tx::{
    output_bitmap_bit, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
    TX_INPUTS, TX_OUTPUTS,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture(tip: u64, inputs: usize) -> (ChainView, PagedSpendIntent) {
    let owner = Address([0x31; 32]);
    let mut state = ChainState::with_log_slots(10);
    let epoch = tx_epoch_anchor_height_for_child(tip + 1);
    let mut header = noid_chain::consensus::genesis_header();
    header.height = epoch;
    let deltas = (0..inputs)
        .map(|index| {
            (
                index as u32,
                SlotValue::with_owner_fields(1_000_000, index as u64 + 42, owner.as_fields()),
            )
        })
        .collect::<Vec<_>>();
    state.state.apply_delta(&deltas).unwrap();
    let view = ChainView::new(
        tip,
        HashMap::from([(epoch, header)]),
        inputs as u64,
        state.state,
    );
    let fee =
        fee_breakdown(inputs as u64, 1, inputs as u64, view.log_slots()).required_total + 1000;
    let count = inputs.div_ceil(TX_INPUTS);
    let pages = (0..count)
        .map(|page| {
            let mut body = TxBody {
                epoch_anchor: view.user_epoch_anchor_id,
                fee: if page == 0 { fee } else { 0 },
                input_owner: owner,
                inputs: [TxInput::dummy(); TX_INPUTS],
                outputs: [TxOutput::dummy(); TX_OUTPUTS],
                validity_bitmap: 0,
                is_coinbase: false,
            };
            for slot in 0..TX_INPUTS {
                let index = page * TX_INPUTS + slot;
                if index < inputs {
                    body.inputs[slot] = TxInput {
                        slot_index: index as u32,
                        amount: 1_000_000,
                        creation_id: index as u64 + 42,
                    };
                    body.validity_bitmap |= 1 << slot;
                }
            }
            if page == 0 {
                body.validity_bitmap |= PAGED_SPEND_START_BIT | output_bitmap_bit(0);
                body.outputs[0] = TxOutput {
                    slot_index: 900,
                    amount: inputs as u64 * 1_000_000 - fee,
                    owner: Address([0x42; 32]),
                };
            }
            if page + 1 == count {
                body.validity_bitmap |= PAGED_SPEND_END_BIT;
            }
            TxPage::new(body).unwrap()
        })
        .collect();
    // These tests isolate admission scheduling. The injected executor records
    // its invocation instead of doing cryptography; authorization verification
    // itself remains covered by the existing real-proof integration tests.
    (view, PagedSpendIntent::new(pages, vec![0x91; 32]).unwrap())
}

#[test]
fn resources_must_fit_one_class_at_the_candidate_height() {
    let Some(h) = V2_ACTIVATION_HEIGHT else {
        return;
    };
    let limits = MempoolConfig::default().with_v2_block_budgets([
        BlockSelectionBudget {
            pages: 63,
            live_inputs: 504,
            contract_calls: 63,
            native_headers: 0,
            native_records: 0,
            owner_authorizations: 63,
            financial: None,
        },
        BlockSelectionBudget {
            pages: 206,
            live_inputs: 384,
            contract_calls: 26,
            native_headers: 0,
            native_records: 0,
            owner_authorizations: 206,
            financial: None,
        },
    ]);
    check_candidate_resources(&limits, h - 2, 128, 1020, 0).unwrap();
    check_candidate_resources(&limits, h - 1, 63, 504, 0).unwrap();
    assert!(matches!(
        check_candidate_resources(&limits, h - 1, 64, 385, 0),
        Err(SubmitError::InputLimitExceeded {
            max_inputs: 384,
            ..
        })
    ));
    assert!(matches!(
        check_candidate_resources(&limits, h - 1, 64, 64, 27),
        Err(SubmitError::NoProofClass { .. })
    ));
    let daily = h + 2880 - 1;
    assert!(matches!(
        check_candidate_resources(&limits, daily - 1, 63, 400, 0),
        Err(SubmitError::InputLimitExceeded {
            max_inputs: 384,
            ..
        })
    ));
    check_candidate_resources(&limits, daily, 63, 400, 0).unwrap();
    check_candidate_resources(&limits, h - 2, 64, 505, 0).unwrap();
    assert!(matches!(
        check_candidate_resources(&limits, u64::MAX, 1, 1, 0),
        Err(SubmitError::Internal(_))
    ));
}

#[test]
fn v2_requires_a_bank_but_legacy_admission_does_not() {
    let Some(h) = V2_ACTIVATION_HEIGHT else {
        return;
    };
    let config = MempoolConfig::default();
    check_candidate_resources(&config, h - 2, 128, 1020, 0).unwrap();
    assert!(matches!(
        check_candidate_resources(&config, h - 1, 1, 1, 0),
        Err(SubmitError::V2LimitsUnavailable)
    ));
}

#[tokio::test]
async fn one_over_is_rejected_before_authorization_while_the_limit_is_admitted() {
    let Some(h) = V2_ACTIVATION_HEIGHT else {
        return;
    };
    for inputs in [504, 505] {
        let (view, intent) = fixture(h - 1, inputs);
        let invoked = Arc::new(AtomicUsize::new(0));
        let counter = invoked.clone();
        let pool = AsyncMempool::new(view, test_config()).with_authorization_verification_executor(
            Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        let bytes = intent.to_bytes().unwrap();
        let result = pool.submit(intent, bytes).await;
        if inputs == 504 {
            result.unwrap();
            assert_eq!(pool.len().await, 1);
            assert_eq!(invoked.load(Ordering::SeqCst), 1);
        } else {
            assert!(matches!(
                result,
                Err(SubmitError::InputLimitExceeded {
                    actual: 505,
                    max_inputs: 504,
                })
            ));
            assert!(pool.is_empty().await);
            assert_eq!(invoked.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn a_fork_during_authorization_is_rechecked_before_admission() {
    let Some(h) = V2_ACTIVATION_HEIGHT else {
        return;
    };
    let (view, intent) = fixture(h - 2, 505);
    let after = fixture(h - 1, 505).0;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let started = Arc::new(std::sync::Mutex::new(Some(started_tx)));
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release = Arc::new(std::sync::Mutex::new(release_rx));
    let pool = AsyncMempool::new(view, test_config()).with_authorization_verification_executor(
        Arc::new(move |_| {
            started.lock().unwrap().take().unwrap().send(()).unwrap();
            release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            Ok(())
        }),
    );
    let submitting = pool.clone();
    let bytes = intent.to_bytes().unwrap();
    let task = tokio::spawn(async move { submitting.submit(intent, bytes).await });
    started_rx.await.unwrap();
    pool.on_new_block(&[], h - 1, after).await;
    release_tx.send(()).unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(SubmitError::InputLimitExceeded {
            actual: 505,
            max_inputs: 504,
        })
    ));
    assert!(pool.is_empty().await);
    assert!(pool.reserved_input_slots().await.is_empty());
    assert!(pool.reserved_output_slots().await.is_empty());
}

#[tokio::test]
async fn crossing_the_fork_evicts_and_reorg_restores_legacy_admission() {
    let Some(h) = V2_ACTIVATION_HEIGHT else {
        return;
    };
    let (before, intent) = fixture(h - 2, 505);
    let pool = AsyncMempool::new(before.clone(), test_config())
        .with_authorization_verification_executor(Arc::new(|_| Ok(())));
    let bytes = intent.to_bytes().unwrap();
    let hash = pool.submit(intent.clone(), bytes.clone()).await.unwrap();
    let mut events = pool.subscribe();
    let after = fixture(h - 1, 505).0;
    assert_eq!(before.user_epoch_anchor_id, after.user_epoch_anchor_id);
    pool.on_new_block(&[], h - 1, after).await;
    assert!(pool.is_empty().await);
    assert!(pool.reserved_input_slots().await.is_empty());
    assert!(pool.reserved_output_slots().await.is_empty());
    assert!(
        matches!(events.recv().await.unwrap(), MempoolEvent::TxEvicted {
        hash: evicted, reason: EvictReason::BlockCapacityChanged,
    } if evicted == hash)
    );
    pool.on_new_block(&[], h - 2, before).await;
    assert_eq!(pool.submit(intent, bytes).await.unwrap(), hash);
    assert_eq!(pool.len().await, 1);
}
