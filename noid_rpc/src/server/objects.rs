// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::object_types::*;
use noid_block::contract_receipt::{ObjectTransitionReceipt, MAX_RECEIPT_BYTES};
use noid_tx::experimental_object::{
    applications, integer_program, policy, ObjectOpening, ObjectRules, OPENING_BYTES,
};

pub(super) async fn protocol_info(handler: &RpcHandler) -> RpcResult<ObjectProtocolInfo> {
    use noid_recursive::acceptance::history_step::v2::banked::Class;
    let tip_height = handler.chain.read().await.tip_height();
    let height = tip_height
        .checked_add(1)
        .ok_or_else(|| rpc_err("height exhausted"))?;
    let config = handler
        .history_step_runtime
        .as_deref()
        .and_then(|runtime| runtime.v2().ok())
        .map(|runtime| runtime.bank().config());
    let classes = config
        .map(|bank| {
            Class::ALL
                .into_iter()
                .map(|class| {
                    let config = bank.class(class);
                    ObjectClassLimits {
                        class: match class {
                            Class::Small => "small",
                            Class::Large => "large",
                        }
                        .into(),
                        pages: config.pages(),
                        live_inputs: config.max_live_inputs(),
                        contract_calls: config.contract_slots(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(ObjectProtocolInfo {
        tip_height,
        activation_height: noid_chain::consensus::params::V2_ACTIVATION_HEIGHT,
        active_at_next_block: noid_chain::consensus::params::v2_active(height),
        runtime_available: config.is_some(),
        next_block_time_seconds: noid_chain::consensus::forks::ACTIVE_SCHEDULE.block_time(height),
        abi_version: noid_tx::experimental_object::OBJECT_VERSION,
        instructions: integer_program::PROGRAM_STEPS,
        persistent_registers: 2,
        classes,
    })
}

pub(super) fn opening(encoded: &str) -> RpcResult<ObjectOpening> {
    ObjectOpening::from_bytes(&decode_bounded_hex(
        "object opening",
        encoded,
        OPENING_BYTES,
    )?)
    .map_err(|e| rpc_err(e.to_string()))
}

pub(super) fn describe(opening: &ObjectOpening) -> RpcResult<ObjectInfo> {
    opening.validate().map_err(|e| rpc_err(e.to_string()))?;
    let modes = opening.rules.modes;
    Ok(ObjectInfo {
        abi_version: noid_tx::experimental_object::OBJECT_VERSION,
        state: integer_program::unpack_state(opening.state).map(ObjectInteger),
        address: opening.root().to_bech32(),
        opening_hex: hex::encode(opening.to_bytes().map_err(|e| rpc_err(e.to_string()))?),
        code_id: hex::encode(opening.code_id()),
        state_hex: format!("{:032x}", opening.state.0),
        program: std::array::from_fn(|step| {
            let instruction = integer_program::Instruction::from_fields(opening.program[step])
                .expect("opening validated above");
            ObjectProgramStep {
                opcode: instruction.opcode,
                destination: instruction.destination,
                left: instruction.left,
                right: instruction.right,
                predicate: instruction.predicate,
                immediate: ObjectInteger(instruction.immediate),
            }
        }),
        claim_authority: opening.claim_authority.to_bech32(),
        recovery_authority: opening.recovery_authority.to_bech32(),
        claim_recipient: opening.claim_recipient.to_bech32(),
        recovery_recipient: opening.recovery_recipient.to_bech32(),
        deadline_height: opening.deadline,
        max_fee_micronoid: opening.rules.max_fee,
        max_payout_micronoid: opening.rules.max_payout,
        min_retained_micronoid: opening.rules.min_retained,
        claim_can_continue: modes & policy::CLAIM_CONTINUE != 0,
        claim_can_close: modes & policy::CLAIM_CLOSE != 0,
        recovery_can_continue: modes & policy::RECOVERY_CONTINUE != 0,
        recovery_can_close: modes & policy::RECOVERY_CLOSE != 0,
        unrestricted_payout_recipient: modes & policy::ANY_PAYOUT_RECIPIENT != 0,
    })
}

pub(super) fn create(definition: ObjectDefinition) -> RpcResult<ObjectInfo> {
    let object = match definition {
        ObjectDefinition::RefundablePayment {
            payer,
            payee,
            expiry_height,
            max_fee_micronoid,
        } => applications::refundable_payment(
            parse_address_param(&payer)?,
            parse_address_param(&payee)?,
            expiry_height,
            max_fee_micronoid,
        ),
        ObjectDefinition::TimelockedVault {
            owner,
            unlock_height,
            max_fee_micronoid,
        } => applications::timelocked_vault(
            parse_address_param(&owner)?,
            unlock_height,
            max_fee_micronoid,
        ),
        ObjectDefinition::AllowanceWallet {
            spending_key,
            recovery_key,
            payout_recipient,
            recover_at,
            max_fee_micronoid,
            max_payout_micronoid,
            min_retained_micronoid,
        } => applications::allowance_wallet(
            parse_address_param(&spending_key)?,
            parse_address_param(&recovery_key)?,
            payout_recipient
                .as_deref()
                .map(parse_address_param)
                .transpose()?,
            recover_at,
            max_fee_micronoid,
            max_payout_micronoid,
            min_retained_micronoid,
        ),
        ObjectDefinition::PeriodBudgetWallet {
            spending_key,
            recovery_key,
            payout_recipient,
            start_height,
            period_blocks,
            budget_micronoid,
            recover_at,
            max_fee_micronoid,
            max_payout_micronoid,
            min_retained_micronoid,
        } => applications::period_budget_wallet(
            parse_address_param(&spending_key)?,
            parse_address_param(&recovery_key)?,
            payout_recipient
                .as_deref()
                .map(parse_address_param)
                .transpose()?,
            applications::PeriodBudget {
                start_height,
                period_blocks,
                budget: budget_micronoid,
                recover_at,
                max_fee: max_fee_micronoid,
                max_payout: max_payout_micronoid,
                min_retained: min_retained_micronoid,
            },
        )
        .map_err(|e| rpc_err(e.to_string()))?,
        ObjectDefinition::RecurringPayment {
            payer,
            payee,
            first_due_height,
            period_blocks,
            payment_micronoid,
            recover_at,
            max_fee_micronoid,
        } => applications::recurring_payment(
            parse_address_param(&payer)?,
            parse_address_param(&payee)?,
            applications::RecurringPayment {
                first_due_height,
                period_blocks,
                payment: payment_micronoid,
                recover_at,
                max_fee: max_fee_micronoid,
            },
        )
        .map_err(|e| rpc_err(e.to_string()))?,
        ObjectDefinition::TrancheVesting {
            beneficiary,
            first_unlock_height,
            period_blocks,
            tranche_micronoid,
            mature_at,
            max_fee_micronoid,
        } => applications::tranche_vesting(
            parse_address_param(&beneficiary)?,
            applications::TrancheVesting {
                first_unlock_height,
                period_blocks,
                tranche_amount: tranche_micronoid,
                mature_at,
                max_fee: max_fee_micronoid,
            },
        )
        .map_err(|e| rpc_err(e.to_string()))?,
        ObjectDefinition::CustomProgram { definition } => custom_program(definition)?,
        ObjectDefinition::Custom { opening_hex } => opening(&opening_hex)?,
    };
    describe(&object)
}

fn custom_program(definition: ObjectProgramDefinition) -> RpcResult<ObjectOpening> {
    if definition.program.len() > integer_program::PROGRAM_STEPS {
        return Err(rpc_err("integer program exceeds 16 instructions"));
    }
    let mut program = integer_program::EMPTY_PROGRAM;
    for (target, step) in program.iter_mut().zip(definition.program) {
        *target = integer_program::Instruction {
            opcode: step.opcode,
            destination: step.destination,
            left: step.left,
            right: step.right,
            predicate: step.predicate,
            immediate: step.immediate.0,
        }
        .to_fields();
    }
    let modes = (u8::from(definition.claim_can_continue) * policy::CLAIM_CONTINUE)
        | (u8::from(definition.claim_can_close) * policy::CLAIM_CLOSE)
        | (u8::from(definition.recovery_can_continue) * policy::RECOVERY_CONTINUE)
        | (u8::from(definition.recovery_can_close) * policy::RECOVERY_CLOSE)
        | (u8::from(definition.unrestricted_payout_recipient) * policy::ANY_PAYOUT_RECIPIENT);
    let object = ObjectOpening {
        program,
        state: integer_program::pack_state(definition.state.map(|value| value.0)),
        claim_authority: parse_address_param(&definition.claim_authority)?,
        recovery_authority: parse_address_param(&definition.recovery_authority)?,
        claim_recipient: parse_address_param(&definition.claim_recipient)?,
        recovery_recipient: parse_address_param(&definition.recovery_recipient)?,
        deadline: definition.deadline_height,
        rules: ObjectRules {
            max_fee: definition.max_fee_micronoid,
            max_payout: definition.max_payout_micronoid,
            min_retained: definition.min_retained_micronoid,
            modes,
        },
    };
    object.validate().map_err(|e| rpc_err(e.to_string()))?;
    Ok(object)
}

pub(super) async fn status(
    handler: &RpcHandler,
    opening_hex: String,
    slot_index: u32,
) -> RpcResult<ObjectStatus> {
    let opening = opening(&opening_hex)?;
    let chain = handler.chain.read().await;
    let tip_height = chain.tip_header().height;
    let next_call_height = tip_height
        .checked_add(1)
        .ok_or_else(|| rpc_err("height exhausted"))?;
    let slot = read_canonical_slot(&chain, slot_index, &mut HashMap::new()).map_err(rpc_err)?;
    let mut owner = [0; 32];
    owner[..16].copy_from_slice(&slot.owner_hi.0.to_le_bytes());
    owner[16..].copy_from_slice(&slot.owner_lo.0.to_le_bytes());
    let owner = noid_poseidon2b::primitives::Address(owner);
    let empty = slot == noid_chain::fri_state::SlotValue::EMPTY;
    Ok(ObjectStatus {
        object: describe(&opening)?,
        slot: SlotInfo {
            slot_index,
            value: slot.amount(),
            creation_id: slot.creation_id(),
            owner: if empty {
                String::new()
            } else {
                owner.to_bech32()
            },
            empty,
        },
        matches_opening: !empty && owner == opening.root(),
        tip_height,
        next_call_height,
        active_authority: if next_call_height < opening.deadline {
            opening.claim_authority
        } else {
            opening.recovery_authority
        }
        .to_bech32(),
    })
}

pub(super) async fn instances(
    handler: &RpcHandler,
    opening_hex: String,
    from_slot: u32,
    limit: u32,
) -> RpcResult<ObjectInstances> {
    let object = opening(&opening_hex)?;
    let address = object.root().to_bech32();
    let chain = handler.chain.read().await;
    let page = chain
        .store
        .get_verified_owner_page(&object.root().0, from_slot, limit as usize)
        .map_err(|e| rpc_err(e.to_string()))?;
    Ok(ObjectInstances {
        address: address.clone(),
        height: page.height,
        tip_hash: hex::encode(page.tip_hash),
        next_slot: page.next_slot,
        slots: page
            .utxos
            .into_iter()
            .map(|utxo| SlotInfo {
                slot_index: utxo.slot_index,
                value: utxo.amount,
                creation_id: utxo.creation_id,
                owner: address.clone(),
                empty: false,
            })
            .collect(),
    })
}

pub(super) async fn known_states(
    handler: &RpcHandler,
    opening_hex: String,
    after_root: Option<String>,
    limit: u32,
) -> RpcResult<ObjectKnownStates> {
    if !(1..=64).contains(&limit) {
        return Err(rpc_err("related contract page must contain 1..64 terms"));
    }
    let opening = opening(&opening_hex)?;
    let after = after_root
        .map(|text| -> RpcResult<[u8; 32]> {
            decode_bounded_hex("object cursor", &text, 32)?
                .try_into()
                .map_err(|_| rpc_err("object cursor must be 32 bytes"))
        })
        .transpose()?;
    let wallet = Arc::clone(&handler.wallet);
    let page = tokio::task::spawn_blocking(move || {
        wallet.related_object_openings(&opening, after, limit as usize)
    })
    .await
    .map_err(|error| rpc_err(error.to_string()))?
    .map_err(rpc_err)?;
    let chain = handler.chain.read().await;
    let mut states = Vec::with_capacity(page.openings.len());
    for opening in page.openings {
        let balance = chain
            .store
            .get_verified_owner_page(&opening.root().0, 0, 1)
            .map_err(|error| rpc_err(error.to_string()))?;
        states.push(ObjectKnownState {
            object: describe(&opening)?,
            has_balance: !balance.utxos.is_empty(),
        });
    }
    Ok(ObjectKnownStates {
        states,
        height: chain.tip_height(),
        tip_hash: hex::encode(noid_chain::block_id(chain.tip_header())),
        next_root: page.next_root.map(hex::encode),
    })
}

fn call_details(
    opening: &ObjectOpening,
    page: &noid_tx::TxPage,
    height: u64,
) -> RpcResult<ObjectCallDetails> {
    let checked = opening
        .check_call(page, height)
        .map_err(|e| rpc_err(e.to_string()))?;
    let paid = &page.body.outputs[usize::from(!checked.terminal)];
    Ok(ObjectCallDetails {
        height,
        txid: hex::encode(
            noid_tx::hash_paged_spend(std::slice::from_ref(page))
                .map_err(|e| rpc_err(e.to_string()))?
                .0,
        ),
        terminal: checked.terminal,
        authority: checked.authority.to_bech32(),
        original: describe(opening)?,
        successor: if checked.terminal {
            None
        } else {
            Some(describe(&opening.successor(checked.next))?)
        },
        input_micronoid: page.body.inputs[0].amount,
        fee_micronoid: page.body.fee,
        retained_micronoid: if checked.terminal {
            0
        } else {
            page.body.outputs[0].amount
        },
        payout: (paid.amount != 0).then(|| ObjectPayout {
            address: paid.owner.to_bech32(),
            amount_micronoid: paid.amount,
        }),
    })
}

pub(super) async fn activity(
    handler: &RpcHandler,
    opening_hex: String,
    after: Option<String>,
    limit: u32,
) -> RpcResult<ObjectActivityPage> {
    if !(1..=64).contains(&limit) {
        return Err(rpc_err("contract activity page must contain 1..64 calls"));
    }
    let opening = opening(&opening_hex)?;
    let wallet = Arc::clone(&handler.wallet);
    let page = tokio::task::spawn_blocking(move || {
        wallet.object_receipts(&opening, after.as_deref(), limit as usize)
    })
    .await
    .map_err(|e| rpc_err(e.to_string()))?
    .map_err(rpc_err)?;
    let chain = handler.chain.read().await;
    let entries = page
        .receipts
        .into_iter()
        .map(|record| {
            // The small record binds its body and opening to this header's Merkle
            // root. The node already verified the selected chain's block proof.
            let canonical = chain
                .store
                .get_header(record.header.height)
                .map_err(|e| rpc_err(e.to_string()))?
                == Some(record.header);
            Ok(ObjectActivityEntry {
                call: call_details(&record.opening, &record.page, record.header.height)?,
                block_hash: hex::encode(noid_chain::block_id(&record.header)),
                canonical,
            })
        })
        .collect::<RpcResult<_>>()?;
    Ok(ObjectActivityPage {
        height: chain.tip_height(),
        tip_hash: hex::encode(noid_chain::block_id(chain.tip_header())),
        entries,
        next_cursor: page.next_cursor,
    })
}

struct PreparedObjectCall {
    opening: ObjectOpening,
    page: noid_tx::TxPage,
    height: u64,
    fee: u64,
}

/// Caller holds the wallet operation gate through preview or authorization.
/// Both paths resolve the same canonical incarnation and execute the program.
async fn prepare_call(
    handler: &RpcHandler,
    request: &ObjectCallRequest,
) -> RpcResult<PreparedObjectCall> {
    if let Some(expected) = &request.expected_authority {
        if handler
            .wallet
            .active_address()
            .as_ref()
            .map(|(_, address)| address)
            != Some(expected)
        {
            return Err(rpc_err(
                "active wallet address changed; review the call again",
            ));
        }
    }
    let opening = opening(&request.opening_hex)?;
    if request.terminal && request.payout.is_some() {
        return Err(rpc_err(
            "closing a contract does not accept a second payment",
        ));
    }
    let (reserved_inputs, reserved_outputs) = handler.mempool.reserved_slots().await;
    if reserved_inputs.contains(&request.slot_index) {
        return Err(rpc_err("contract incarnation already has a pending call"));
    }
    let floor = handler.mempool.fee_floor().await;
    let (page, height, fee) = {
        let chain = handler.chain.read().await;
        let tip = chain.tip_header();
        let height = tip
            .height
            .checked_add(1)
            .ok_or_else(|| rpc_err("height exhausted"))?;
        handler.require_contracts_for_height(height)?;
        if request
            .expected_call_height
            .is_some_and(|expected| expected != height)
        {
            return Err(rpc_err(
                "inclusion height changed; preview and authorize the call again",
            ));
        }
        if request
            .expected_recovery
            .is_some_and(|expected| expected != (height >= opening.deadline))
        {
            return Err(rpc_err(
                "contract deadline branch changed; review the call again",
            ));
        }
        let slot = read_canonical_slot(&chain, request.slot_index, &mut HashMap::new())
            .map_err(rpc_err)?;
        let root = opening.root().as_fields();
        if slot.owner_hi != root[0]
            || slot.owner_lo != root[1]
            || slot.creation_id() != request.creation_id
            || slot.amount() == 0
        {
            return Err(rpc_err(
                "opening or incarnation does not match the current contract State",
            ));
        }
        let output_count = 1 + usize::from(request.payout.is_some());
        let minimum = noid_chain::consensus::fee_breakdown(
            1,
            output_count as u64,
            tip.active_slot_count,
            tip.log_slots,
        )
        .required_total
        .max(floor);
        let fee = if request.fee_micronoid == 0 {
            minimum
        } else {
            request.fee_micronoid
        };
        if fee < minimum {
            return Err(rpc_err(format!(
                "call requires at least {minimum} micronoid fee"
            )));
        }
        let slots = collect_empty_slot_hints(
            &chain,
            &reserved_outputs,
            tip.alloc_counter ^ request.creation_id,
            output_count,
        )
        .map_err(rpc_err)?;
        if slots.len() != output_count {
            return Err(rpc_err("not enough empty output slots"));
        }
        let input = noid_tx::TxInput {
            slot_index: request.slot_index,
            amount: slot.amount(),
            creation_id: request.creation_id,
        };
        let anchor = next_user_epoch_anchor(&chain).map_err(rpc_err)?;
        let page = match request.payout.as_ref() {
            Some(payout) => opening.build_payment(
                input,
                slots[0],
                fee,
                anchor,
                height,
                noid_tx::TxOutput {
                    slot_index: slots[1],
                    amount: payout.amount_micronoid,
                    owner: parse_address_param(&payout.address)?,
                },
            ),
            None => opening.build_call(input, slots[0], fee, anchor, height, request.terminal),
        }
        .map_err(|e| rpc_err(e.to_string()))?;
        (page, height, fee)
    };
    if let Some(expected) = &request.expected_txid {
        let expected = decode_bounded_hex("reviewed transaction id", expected, 32)?;
        let actual = noid_tx::hash_paged_spend(std::slice::from_ref(&page))
            .map_err(|e| rpc_err(e.to_string()))?;
        if expected.as_slice() != actual.0 {
            return Err(rpc_err(
                "call body changed; preview and authorize the call again",
            ));
        }
    }
    Ok(PreparedObjectCall {
        opening,
        page,
        height,
        fee,
    })
}

pub(super) async fn preview(
    handler: &RpcHandler,
    request: ObjectCallRequest,
) -> RpcResult<ObjectCallPreview> {
    let _operation = handler.wallet_operation_gate.lock().await;
    let PreparedObjectCall {
        opening,
        page,
        height,
        fee,
    } = prepare_call(handler, &request).await?;
    let checked = opening
        .check_call(&page, height)
        .map_err(|e| rpc_err(e.to_string()))?;
    let paid = if checked.terminal {
        &page.body.outputs[0]
    } else {
        &page.body.outputs[1]
    };
    Ok(ObjectCallPreview {
        txid: hex::encode(
            noid_tx::hash_paged_spend(std::slice::from_ref(&page))
                .map_err(|e| rpc_err(e.to_string()))?
                .0,
        ),
        call_height: height,
        authority: checked.authority.to_bech32(),
        recovery: height >= opening.deadline,
        terminal: checked.terminal,
        fee_micronoid: fee,
        retained_micronoid: if checked.terminal {
            0
        } else {
            page.body.outputs[0].amount
        },
        payout: (paid.amount != 0).then(|| ObjectPayout {
            address: paid.owner.to_bech32(),
            amount_micronoid: paid.amount,
        }),
        successor: if checked.terminal {
            None
        } else {
            Some(describe(&opening.successor(checked.next))?)
        },
    })
}

pub(super) async fn call(
    handler: &RpcHandler,
    request: ObjectCallRequest,
) -> RpcResult<ObjectCallResult> {
    let _operation = handler.wallet_operation_gate.lock().await;
    let PreparedObjectCall {
        opening,
        page,
        height,
        fee,
    } = prepare_call(handler, &request).await?;
    let checked = opening
        .check_call(&page, height)
        .map_err(|e| rpc_err(e.to_string()))?;
    let successor = (!request.terminal).then(|| opening.successor(checked.next));
    let txid = noid_tx::hash_paged_spend(std::slice::from_ref(&page))
        .map_err(|e| rpc_err(e.to_string()))?;
    let output_slot = page.body.outputs[0].slot_index;
    let output_slots: Vec<_> = page
        .body
        .live_outputs()
        .map(|(_, output)| output.slot_index)
        .collect();
    let output_count = output_slots.len();
    let (amount, recipient) = if request.terminal {
        (page.body.outputs[0].amount, page.body.outputs[0].owner)
    } else {
        (page.body.outputs[1].amount, page.body.outputs[1].owner)
    };
    handler
        .wallet
        .remember_object_opening(&opening)
        .map_err(rpc_err)?;
    if let Some(successor) = &successor {
        handler
            .wallet
            .remember_object_opening(successor)
            .map_err(rpc_err)?;
    }
    let wallet = Arc::clone(&handler.wallet);
    let bytes = tokio::task::spawn_blocking(move || {
        noid_miner::install_wallet_proof_cpu(|| wallet.build_object_call(opening, page, height))
            .map_err(|e| e.to_string())?
    })
    .await
    .map_err(|e| rpc_err(e.to_string()))?
    .map_err(rpc_err)?;
    let reservation = PendingAdmissionGuard::reserve(
        Arc::clone(&handler.wallet),
        txid.0,
        vec![request.slot_index],
        output_slots,
        amount,
        recipient.0,
    )
    .map_err(rpc_err)?;
    let admitted = handler
        .wallet_submission_mempool
        .submit_encoded(bytes)
        .await
        .map_err(|e| rpc_err(e.to_string()))?;
    if admitted != txid {
        return Err(rpc_err("admitted contract transaction identity changed"));
    }
    reservation.commit();
    Ok(ObjectCallResult {
        transaction: WalletSendResult {
            txid: hex::encode(txid.0),
            amount_micronoid: amount,
            fee_micronoid: fee,
            input_count: 1,
            output_count,
        },
        call_height: height,
        successor: successor.as_ref().map(describe).transpose()?,
        output_slot,
    })
}

pub(super) async fn export_receipt(
    handler: &RpcHandler,
    opening_hex: String,
    txid: String,
) -> RpcResult<String> {
    let opening = opening(&opening_hex)?;
    let txid: [u8; 32] = decode_bounded_hex("transaction id", &txid, 32)?
        .try_into()
        .map_err(|_| rpc_err("transaction id length"))?;
    let chain = handler.chain.read().await;
    // The transaction index may rotate with body retention. A saved receipt
    // only needs its permanent canonical header, even after both are pruned.
    if let Ok(bytes) = handler.wallet.load_object_receipt(txid) {
        let receipt = ObjectTransitionReceipt::from_bytes(&bytes).map_err(rpc_err)?;
        if receipt.opening == opening
            && chain
                .store
                .get_header(receipt.header.height)
                .map_err(|e| rpc_err(e.to_string()))?
                == Some(receipt.header)
        {
            return Ok(hex::encode(bytes));
        }
    }
    let (height, _) = chain
        .store
        .get_tx_index(&txid)
        .map_err(|e| rpc_err(e.to_string()))?
        .ok_or_else(|| rpc_err("contract transaction is not confirmed"))?;
    let header = chain
        .store
        .get_header(height)
        .map_err(|e| rpc_err(e.to_string()))?
        .ok_or_else(|| rpc_err("canonical header missing"))?;
    let block_bytes = chain
        .store
        .get_recent_canonical_block(height)
        .map_err(|e| rpc_err(e.to_string()))?
        .ok_or_else(|| rpc_err("body was pruned before this wallet retained the object receipt"))?;
    let block = noid_chain::Block::from_bytes(&block_bytes)
        .map_err(|e| rpc_err(format!("receipt block: {e:?}")))?;
    if block.header != header {
        return Err(rpc_err("retained body is not canonical"));
    }
    let stream = noid_chain::validate_block_page_stream(&block.transactions)
        .map_err(|e| rpc_err(e.to_string()))?;
    let index = stream
        .groups
        .iter()
        .position(|group| group.spend.logical_txid.0 == txid)
        .ok_or_else(|| rpc_err("contract transaction missing from its block"))?;
    let receipt = crate::object_receipts::from_store(&chain.store, &block, index, opening)
        .map_err(rpc_err)?
        .ok_or_else(|| rpc_err("recursive proof for receipt is not available yet"))?;
    let bytes = receipt.to_bytes().map_err(rpc_err)?;
    handler
        .wallet
        .remember_object_receipt(txid, &bytes)
        .map_err(rpc_err)?;
    Ok(hex::encode(bytes))
}

pub(super) async fn verify_receipt(
    handler: &RpcHandler,
    encoded: String,
) -> RpcResult<ObjectReceiptResult> {
    // At most one RPC receipt worker holds proof data. The permit moves into
    // the blocking worker, so cancellation cannot release capacity early.
    static PERMITS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    let permit = Arc::clone(PERMITS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1))))
        .try_acquire_owned()
        .map_err(|_| rpc_err("receipt verifier is busy; retry shortly"))?;
    let bytes = decode_bounded_hex("object receipt", &encoded, MAX_RECEIPT_BYTES)?;
    let receipt = ObjectTransitionReceipt::from_bytes(&bytes).map_err(rpc_err)?;
    let header = handler
        .chain
        .read()
        .await
        .store
        .get_header(receipt.header.height)
        .map_err(|e| rpc_err(e.to_string()))?
        .ok_or_else(|| rpc_err("receipt header is not on this node's selected chain"))?;
    let runtime = handler
        .history_step_runtime
        .clone()
        .ok_or_else(|| rpc_err("HistoryStep verifier unavailable"))?;
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        noid_miner::install_inbound_verifier_cpu(|| -> Result<ObjectReceiptResult, String> {
            let origin = runtime
                .requested_origin(&receipt.terminal)?
                .ok_or("receipt is not a scheduled v2 contract")?;
            let origin = runtime.verified_origin(&origin)?;
            receipt.verify_v2(runtime.v2()?, &origin, &header)?;
            Ok(ObjectReceiptResult {
                valid: true,
                call: call_details(&receipt.opening, &receipt.page, header.height)
                    .map_err(|e| e.to_string())?,
            })
        })
        .map_err(|e| e.to_string())?
    })
    .await
    .map_err(|e| rpc_err(e.to_string()))?
    .map_err(rpc_err)?;
    // A complete proof is still valid for an orphan. Recheck chain selection
    // after expensive verification so a concurrent reorg cannot return a stale
    // claim of canonical confirmation.
    if handler
        .chain
        .read()
        .await
        .store
        .get_header(header.height)
        .map_err(|e| rpc_err(e.to_string()))?
        != Some(header)
    {
        return Err(rpc_err(
            "selected chain changed while verifying the receipt",
        ));
    }
    Ok(verified)
}

pub(super) async fn import_receipt(
    handler: &RpcHandler,
    encoded: String,
    expected_opening_hex: Option<String>,
) -> RpcResult<ObjectReceiptResult> {
    let verified = verify_receipt(handler, encoded.clone()).await?;
    if let Some(expected) = expected_opening_hex {
        let expected = opening(&expected)?;
        let original = opening(&verified.call.original.opening_hex)?;
        let next = verified
            .call
            .successor
            .as_ref()
            .map(|next| opening(&next.opening_hex))
            .transpose()?;
        if expected != original && next.as_ref() != Some(&expected) {
            return Err(rpc_err(
                "receipt does not establish the requested contract state",
            ));
        }
    }
    let bytes = decode_bounded_hex("object receipt", &encoded, MAX_RECEIPT_BYTES)?;
    let receipt = ObjectTransitionReceipt::from_bytes(&bytes).map_err(rpc_err)?;
    // Keep chain selection stable while installing public wallet artifacts.
    let chain = handler.chain.read().await;
    if chain
        .store
        .get_header(receipt.header.height)
        .map_err(|e| rpc_err(e.to_string()))?
        != Some(receipt.header)
    {
        return Err(rpc_err(
            "selected chain changed while importing the receipt",
        ));
    }
    handler
        .wallet
        .remember_object_opening(&receipt.opening)
        .map_err(rpc_err)?;
    if let Some(next) = &verified.call.successor {
        handler
            .wallet
            .remember_object_opening(&opening(&next.opening_hex)?)
            .map_err(rpc_err)?;
    }
    let txid = noid_tx::hash_paged_spend(std::slice::from_ref(&receipt.page))
        .map_err(|e| rpc_err(e.to_string()))?
        .0;
    handler
        .wallet
        .remember_object_receipt(txid, &bytes)
        .map_err(rpc_err)?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use integer_program::{Instruction, Opcode, Operand, Predicate, PredicateSource, Register};

    #[test]
    fn typed_custom_program_round_trip_preserves_every_descriptor_bit_and_u64() {
        let owner = noid_poseidon2b::primitives::Address([7; 32]);
        let mut object = applications::timelocked_vault(owner, 300, 50_000);
        let plain = describe(&object).unwrap();
        let step = Instruction {
            opcode: Opcode::AssertLessOrEqual,
            destination: Register::Scratch1,
            left: Operand::InputCreationId,
            right: Operand::PayoutSlot,
            predicate: Predicate {
                source: PredicateSource::Scratch1,
                inverted: true,
            },
            immediate: u64::MAX,
        };
        object.program[15] = step.to_fields();
        object.state = integer_program::pack_state([(1 << 53) + 1, u64::MAX]);
        let info = create(ObjectDefinition::Custom {
            opening_hex: hex::encode(object.to_bytes().unwrap()),
        })
        .unwrap();
        assert_ne!(info.address, plain.address);
        assert_ne!(info.code_id, plain.code_id);
        assert_eq!(info.program[15].opcode, step.opcode);
        assert_eq!(info.program[15].destination, step.destination);
        assert_eq!(info.program[15].left, step.left);
        assert_eq!(info.program[15].right, step.right);
        assert_eq!(info.program[15].predicate, step.predicate);
        assert_eq!(info.program[15].immediate.0, u64::MAX);
        assert_eq!(info.state.map(|value| value.0), [(1 << 53) + 1, u64::MAX]);
        let encoded = serde_json::to_value(&info).unwrap();
        assert_eq!(encoded["state"][0], "9007199254740993");
        assert_eq!(encoded["program"][15]["immediate"], "18446744073709551615");
        let definition: ObjectDefinition = serde_json::from_value(serde_json::json!({
            "kind": "custom_program", "definition": ObjectProgramDefinition::from(&info),
        }))
        .unwrap();
        let reconstructed = create(definition).unwrap();
        assert_eq!(opening(&reconstructed.opening_hex).unwrap(), object);
        assert_eq!(reconstructed.address, info.address);
        assert_eq!(reconstructed.code_id, info.code_id);
        let mut overlong = ObjectProgramDefinition::from(&info);
        overlong.program.push(info.program[0].clone());
        assert!(custom_program(overlong).is_err());
        let mut compact = ObjectProgramDefinition::from(&plain);
        compact.program.clear();
        assert_eq!(
            custom_program(compact).unwrap(),
            opening(&plain.opening_hex).unwrap()
        );
    }

    #[test]
    fn scheduled_api_definitions_enforce_counter_and_due_height_transitions() {
        let owner = noid_poseidon2b::primitives::Address([7; 32]).to_bech32();
        let definitions = [
            serde_json::json!({"kind":"period_budget_wallet","spending_key":owner,
                "recovery_key":owner,"payout_recipient":owner,"start_height":100,
                "period_blocks":20,"budget_micronoid":1_000,"recover_at":300,
                "max_fee_micronoid":50,"max_payout_micronoid":500,"min_retained_micronoid":50}),
            serde_json::json!({"kind":"recurring_payment","payer":owner,"payee":owner,
                "first_due_height":100,"period_blocks":20,"payment_micronoid":200,
                "recover_at":300,"max_fee_micronoid":50}),
            serde_json::json!({"kind":"tranche_vesting","beneficiary":owner,
                "first_unlock_height":100,"period_blocks":20,"tranche_micronoid":200,
                "mature_at":300,"max_fee_micronoid":50}),
        ];
        // Budget stores remaining debit, recurring stores its call count,
        // and vesting stores the cumulative released amount.
        let expected = [[790, 120], [1, 125], [200, 120]];
        for (json, expected_state) in definitions.into_iter().zip(expected) {
            let info = create(serde_json::from_value(json).unwrap()).unwrap();
            let object = opening(&info.opening_hex).unwrap();
            let input = noid_tx::TxInput {
                slot_index: 1,
                amount: 10_000,
                creation_id: 7,
            };
            let payout = noid_tx::TxOutput {
                slot_index: 3,
                amount: 200,
                owner: parse_address_param(&owner).unwrap(),
            };
            assert!(object
                .build_payment(input, 2, 10, [0; 32], 99, payout)
                .is_err());
            let call = object
                .build_payment(input, 2, 10, [0; 32], 105, payout)
                .unwrap();
            let checked = object.check_call(&call, 105).unwrap();
            assert_eq!(integer_program::unpack_state(checked.next), expected_state);
        }
    }
}
