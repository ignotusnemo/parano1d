// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exercise the actual admission, template, prover, local commit and inbound
//! MDBX paths. This is not a daemon/P2P or constrained-receiver benchmark.

use super::*;
use noid_chain::{storage::MdbxChainContext, AcceptedBlockBundle};
use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
use noid_miner::template::{TemplateBuilder, TemplateChainSnapshot};
use noid_miner::{HistoryProtocolRuntime, MiningProofClass, PreparedBlockAttempt};
use noid_recursive::acceptance::history_step::v2::banked::Class;
use noid_tx::experimental_object::{applications as apps, ObjectIntent};
use std::sync::Arc;

pub fn run(args: &[String]) -> Result<()> {
    if args.len() != 7
        || !noid_chain::consensus::params::ISOLATED_V2_FORK_TESTNET
        || !matches!(args[6].as_str(), "fork" | "capacity")
    {
        return Err("usage: noid_v2_capacity joint-produce PACK PIN LEGACY_FIXTURES CANDIDATE BANK_PIN NEW_OUTPUT fork|capacity (isolated-v2-fork-testnet required)".into());
    }
    let pin = |s: &str| -> Result<[u8; 32]> {
        hex::decode(s)
            .map_err(err)?
            .try_into()
            .map_err(|_| "pin length".into())
    };
    let output = PathBuf::from(&args[5]);
    std::fs::create_dir(&output).map_err(|e| format!("new output directory required: {e}"))?;
    let legacy = Arc::new(proof::legacy_runtime(Path::new(&args[0]), pin(&args[1])?)?);
    let [producer_runtime, receiver_runtime] =
        banked::runtime_pair(Path::new(&args[3]), pin(&args[4])?)?;
    let config = producer_runtime.bank().config();
    let producer = HistoryProtocolRuntime::new(
        Some(legacy.clone()),
        Some(producer_runtime.clone()),
        output.join("producer-origins"),
    )?;
    let receiver = HistoryProtocolRuntime::new(
        Some(legacy.clone()),
        Some(receiver_runtime),
        output.join("receiver-origins"),
    )?;
    let large = HistoryProtocolRuntime::new(
        Some(legacy),
        Some(producer_runtime),
        output.join("producer-origins"),
    )?
    .with_large_v2_mining(true);
    let mut producing = MdbxChainContext::open_or_create(&output.join("producer")).map_err(err)?;
    let mut receiving = MdbxChainContext::open_or_create(&output.join("receiver")).map_err(err)?;
    producer.attach_canonical_store(producing.store.clone())?;
    large.attach_canonical_store(producing.store.clone())?;
    receiver.attach_canonical_store(receiving.store.clone())?;
    let cpu = noid_miner::configure_process_cpu_budget(noid_miner::ProcessCpuBudgetMode::ProofOnly)
        .map_err(err)?;
    let base = if args[6] == "fork" {
        config.activation_height() - 1
    } else {
        33
    };
    let setup = Instant::now();
    for height in 1..=base {
        let directory = if height < config.activation_height() {
            &args[2]
        } else {
            &args[3]
        };
        let path = Path::new(directory);
        let bundle = AcceptedBlockBundle::try_from_parts(
            proof::bounded(
                &path.join(format!("h{height:06}.block")),
                noid_chain::consensus::wire_limits::MAX_BLOCK_BYTES,
            )?,
            proof::bounded(&path.join(format!("h{height:06}.terminal")), 1_100_000)?,
        )
        .map_err(err)?;
        apply(&mut producing, &producer, &bundle)?;
        apply(&mut receiving, &receiver, &bundle)?;
        println!(
            "{}",
            json!({"phase":"production_replay","height":height,"memory":memory()})
        );
    }
    let mut state = Chain::replay_for_receiver(
        Path::new(&args[2]),
        Path::new(&args[3]),
        config.class(Class::Small),
        base,
    )?;
    if state.parent() != producing.tip_header() || producing.tip_header() != receiving.tip_header()
    {
        return Err("production replay boundaries differ".into());
    }
    let ghost = noid_recursive::prepare_history_step_ghost_authorization_for_version(
        noid_gkr::ghost_tx::prove_selected_ghost_authorization_for_version(
            config.class(Class::Small).authorization_version(),
        )
        .map_err(err)?,
        config.class(Class::Small).authorization_version(),
    )
    .map_err(err)?;
    println!(
        "{}",
        json!({"phase":"production_setup","ms":elapsed(setup),"cpu":format!("{cpu:?}"),"memory":memory()})
    );
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(err)?;
    let mut run = Production {
        producing,
        receiving,
        producer,
        receiver,
        large,
        ghost,
        output: output.clone(),
        records: Vec::new(),
    };
    executor.block_on(async {
        if args[6] == "fork" {
            run.templates(&mut state).await
        } else {
            run.capacity(&mut state).await
        }
    })?;
    let tip = *run.producing.tip_header();
    let records = std::mem::take(&mut run.records);
    drop(run);
    for directory in ["producer", "receiver"] {
        let context = MdbxChainContext::open_or_create(&output.join(directory)).map_err(err)?;
        if context.tip_header() != &tip || context.state.cached_state_root() != tip.state_root {
            return Err("durable reopen changed the accepted boundary".into());
        }
    }
    let report = json!({"complete":true,"mode":args[6],"tip":tip.height,"bank":args[4],
        "records":records,"durable_reopen":true,"daemon_p2p_qualified":false,"memory":memory()});
    std::fs::write(
        output.join("production.json"),
        serde_json::to_vec_pretty(&report).map_err(err)?,
    )
    .map_err(err)?;
    println!("{report}");
    Ok(())
}

fn apply(
    chain: &mut MdbxChainContext,
    runtime: &HistoryProtocolRuntime,
    bundle: &AcceptedBlockBundle,
) -> Result<()> {
    let block = Block::from_bytes(bundle.block_bytes()).map_err(err)?;
    chain
        .apply_next_block(
            bundle,
            block.header.timestamp,
            |block, state| noid_chain::materialize_accepted_block_state(state, block).map_err(err),
            |claim| {
                noid_miner::install_inbound_verifier_cpu(|| {
                    runtime.verify_terminal(
                        claim.terminal_bytes,
                        &claim.header,
                        &claim.epoch_anchor_header,
                    )
                })
                .map_err(err)?
                .map(|_| ())
            },
        )
        .map_err(err)?;
    Ok(())
}

struct Production {
    producing: MdbxChainContext,
    receiving: MdbxChainContext,
    producer: HistoryProtocolRuntime,
    receiver: HistoryProtocolRuntime,
    large: HistoryProtocolRuntime,
    ghost: PreparedHistoryStepGhostAuthorization,
    output: PathBuf,
    records: Vec<serde_json::Value>,
}

impl Production {
    async fn block(
        &mut self,
        chain: &mut Chain,
        label: &str,
        mut batch: Batch,
        selection: (bool, Class),
        expected_pages: usize,
        expected_calls: usize,
    ) -> Result<()> {
        let height = chain.parent().height + 1;
        batch.prove_authorizations(height)?;
        let pool = AsyncMempool::new(
            ChainView::from_mdbx(&self.producing),
            MempoolConfig::default().with_v2_block_budgets(
                self.producer
                    .v2_admission_budgets()
                    .ok_or("v2 budgets unavailable")?,
            ),
        )
        .with_authorization_verification_executor(Arc::new(|task| {
            noid_miner::install_wallet_verifier_cpu(task).map_err(err)?
        }));
        let admitted = batch.pages.len();
        let admission = Instant::now();
        for (index, (page, proof)) in batch.pages.into_iter().zip(batch.proofs).enumerate() {
            let bundle = noid_gkr::WalletAuthorizationBundle { proof };
            let spend =
                PagedSpendIntent::new(vec![page], bundle.to_bytes().map_err(err)?).map_err(err)?;
            let bytes = match batch.openings.get(index) {
                Some(opening) => ObjectIntent {
                    opening: opening.clone(),
                    spend,
                }
                .to_bytes()
                .map_err(err)?,
                None => spend.to_bytes().map_err(err)?,
            };
            pool.submit_encoded(bytes).await.map_err(err)?;
        }
        let admission_ms = elapsed(admission);
        let (large, expected_class) = selection;
        let runtime = if large { &self.large } else { &self.producer };
        let snapshot = TemplateChainSnapshot::from_context(&mut self.producing).map_err(err)?;
        let time =
            chain.parent().timestamp + runtime.v2()?.bank().config().schedule().block_time(height);
        let template_start = Instant::now();
        let template = TemplateBuilder::new(pool.clone())
            .with_history_protocol(runtime)
            // Deliberately pass the old default: v2 must use its own bank.
            .build_from_snapshot_with_limit(snapshot, address(1), time, 25)
            .await
            .ok_or("no production template")?;
        let template_ms = elapsed(template_start);
        if template.v2_class != Some(expected_class)
            || template.n_user_txs() != expected_pages
            || template.object_openings.len() != expected_calls
        {
            return Err(format!("unexpected production selection: class={:?}, pages={}, calls={}, expected={expected_class:?}/{expected_pages}/{expected_calls}",
                template.v2_class, template.n_user_txs(), template.object_openings.len()));
        }
        let preparation = Instant::now();
        let attempt = noid_miner::install_history_step_phase_cpu(|| {
            PreparedBlockAttempt::prepare(template, runtime, &self.ghost, time)
        })
        .map_err(err)??;
        let preparation_ms = elapsed(preparation);
        if attempt.proof_class() != MiningProofClass::V2(expected_class) {
            return Err("producer class drift".into());
        }
        let pow = Instant::now();
        let nonce = mine(&attempt.pow_header(0));
        let pow_ms = elapsed(pow);
        let committed = attempt
            .prove(runtime, nonce)?
            .commit(&mut self.producing)
            .map_err(err)?;
        let (block, bundle) = committed.into_parts();
        // Parse the wire envelope again before independent inbound validation.
        let received = AcceptedBlockBundle::decode(&bundle.encode()).map_err(err)?;
        let verify = Instant::now();
        apply(&mut self.receiving, &self.receiver, &received)?;
        let verify_apply_ms = elapsed(verify);
        if self.receiving.tip_header() != self.producing.tip_header() {
            return Err("inbound boundary mismatch".into());
        }
        let end = chain
            .accumulator
            .advance(chain.parent(), &block.header)
            .map_err(err)?;
        let root =
            noid_chain::materialize_accepted_block_state(&mut chain.state, &block).map_err(err)?;
        if root != block.header.state_root {
            return Err("independent materialized root differs".into());
        }
        let confirmed = noid_chain::try_compute_logical_txids(&block.transactions).map_err(err)?;
        pool.on_new_block(&confirmed, height, ChainView::from_mdbx(&self.producing))
            .await;
        if pool.len().await != admitted - expected_pages {
            return Err("mempool confirmation cleanup differs".into());
        }
        std::fs::write(
            self.output.join(format!("h{height:06}.block")),
            bundle.block_bytes(),
        )
        .map_err(err)?;
        std::fs::write(
            self.output.join(format!("h{height:06}.terminal")),
            bundle.history_step_terminal_bytes(),
        )
        .map_err(err)?;
        chain.accept(block, end);
        let record = json!({"label":label,"height":height,"pages":expected_pages,"calls":expected_calls,
            "class":expected_class.wire_id(),"auth_ms":batch.auth_ms,"admission_ms":admission_ms,
            "template_ms":template_ms,"preparation_ms":preparation_ms,"pow_ms":pow_ms,
            "verify_apply_ms":verify_apply_ms,"terminal_bytes":bundle.history_step_terminal_bytes().len(),"memory":memory()});
        println!("{record}");
        self.records.push(record);
        Ok(())
    }

    async fn templates(&mut self, chain: &mut Chain) -> Result<()> {
        self.block(
            chain,
            "fork_empty",
            Batch::default(),
            (false, Class::Small),
            0,
            0,
        )
        .await?;
        let claim_height = chain.parent().height + 2;
        let expiry = claim_height + 4;
        let max_fee = 100_000;
        let payout = 200_000;
        let openings = vec![
            apps::refundable_payment(address(2), address(2), expiry, max_fee),
            apps::timelocked_vault(address(2), claim_height, max_fee),
            apps::allowance_wallet(
                address(2),
                address(2),
                Some(address(2)),
                expiry,
                max_fee,
                payout,
                max_fee,
            ),
            apps::period_budget_wallet(
                address(2),
                address(2),
                Some(address(2)),
                apps::PeriodBudget {
                    start_height: claim_height,
                    period_blocks: 2,
                    budget: 1_000_000,
                    recover_at: expiry,
                    max_fee,
                    max_payout: payout,
                    min_retained: max_fee,
                },
            )
            .map_err(err)?,
            apps::recurring_payment(
                address(2),
                address(2),
                apps::RecurringPayment {
                    first_due_height: claim_height,
                    period_blocks: 2,
                    payment: payout,
                    recover_at: expiry,
                    max_fee,
                },
            )
            .map_err(err)?,
            apps::tranche_vesting(
                address(2),
                apps::TrancheVesting {
                    first_unlock_height: claim_height,
                    period_blocks: 2,
                    tranche_amount: payout,
                    mature_at: expiry,
                    max_fee,
                },
            )
            .map_err(err)?,
        ];
        let sources = chain.ordinary_slots();
        if sources.len() < openings.len() {
            return Err("six funding sources required".into());
        }
        let mut objects = Vec::new();
        let mut funding = Batch::default();
        for (source, opening) in sources.into_iter().zip(openings) {
            let [slot] = chain.empty_slots()?;
            let amount = chain
                .input_slot(source)?
                .amount
                .checked_sub(chain.fee(1))
                .ok_or("funding amount")?;
            funding.ordinary(
                chain,
                source,
                [
                    opening.funding_output(slot, amount).map_err(err)?,
                    TxOutput::dummy(),
                ],
                false,
            )?;
            objects.push((slot, opening));
        }
        self.block(
            chain,
            "fund_six_templates",
            funding,
            (false, Class::Small),
            6,
            0,
        )
        .await?;
        for round in 0..=4 {
            let height = chain.parent().height + 1;
            if round % 2 == 1 {
                // Correct controller authorization cannot make scheduled
                // recurring/vesting payments earlier than the proved height.
                for (slot, opening) in objects.iter().rev().take(2) {
                    let [next, payment] = chain.empty_slots()?;
                    if opening
                        .build_payment(
                            chain.input_slot(*slot)?,
                            next,
                            chain.fee(2),
                            chain.epoch_id(),
                            height,
                            TxOutput {
                                slot_index: payment,
                                amount: payout,
                                owner: address(2),
                            },
                        )
                        .is_ok()
                    {
                        return Err("scheduled template allowed an early payment".into());
                    }
                }
                self.block(
                    chain,
                    "between_due_heights",
                    Batch::default(),
                    (false, Class::Small),
                    0,
                    0,
                )
                .await?;
                continue;
            }
            let mut batch = Batch::default();
            let mut successors = Vec::new();
            for (index, (source, opening)) in objects.iter().enumerate() {
                let [next, payment] = chain.empty_slots()?;
                let close = height >= expiry || round == 0 && index < 2;
                let page = if close {
                    opening.build_call(
                        chain.input_slot(*source)?,
                        next,
                        chain.fee(1),
                        chain.epoch_id(),
                        height,
                        true,
                    )
                } else {
                    opening.build_payment(
                        chain.input_slot(*source)?,
                        next,
                        chain.fee(2),
                        chain.epoch_id(),
                        height,
                        TxOutput {
                            slot_index: payment,
                            amount: payout,
                            owner: address(2),
                        },
                    )
                }
                .map_err(err)?;
                if !close {
                    successors.push((
                        next,
                        opening.successor(opening.execute(&page.body, height).map_err(err)?),
                    ));
                }
                batch.pages.push(page);
                batch.openings.push(opening.clone());
            }
            let calls = batch.pages.len();
            // A higher-fee ordinary payment must follow the contract prefix
            // while retaining its own correct authorization and state IDs.
            let source = *chain
                .ordinary_slots()
                .first()
                .ok_or("mixed payment source")?;
            let [slot] = chain.empty_slots()?;
            let amount = chain.input_slot(source)?.amount - chain.fee(1) - 50_000;
            batch.ordinary(
                chain,
                source,
                [
                    TxOutput {
                        slot_index: slot,
                        amount,
                        owner: address(1),
                    },
                    TxOutput::dummy(),
                ],
                false,
            )?;
            batch.pages.last_mut().unwrap().body.fee += 50_000;
            self.block(
                chain,
                "template_calls_and_payment",
                batch,
                (false, Class::Small),
                calls + 1,
                calls,
            )
            .await?;
            objects = successors;
        }
        if !objects.is_empty() {
            return Err("recovery left live test objects".into());
        }
        self.block(
            chain,
            "after_recovery",
            Batch::default(),
            (false, Class::Small),
            0,
            0,
        )
        .await
    }

    async fn capacity(&mut self, chain: &mut Chain) -> Result<()> {
        let small = self
            .producer
            .v2()?
            .bank()
            .config()
            .class(Class::Small)
            .pages();
        let large = self
            .producer
            .v2()?
            .bank()
            .config()
            .class(Class::Large)
            .pages();
        for (enabled, count) in [(false, small), (true, large), (false, small)] {
            let sources = chain.ordinary_slots();
            if sources.len() < large {
                return Err("capacity fixture has too few ordinary notes".into());
            }
            let mut batch = Batch::default();
            for source in sources.into_iter().take(large) {
                let [slot] = chain.empty_slots()?;
                let amount = chain
                    .input_slot(source)?
                    .amount
                    .checked_sub(chain.fee(1))
                    .ok_or("payment balance")?;
                batch.ordinary(
                    chain,
                    source,
                    [
                        TxOutput {
                            slot_index: slot,
                            amount,
                            owner: address(1),
                        },
                        TxOutput::dummy(),
                    ],
                    false,
                )?;
            }
            self.block(
                chain,
                "manual_large_production",
                batch,
                (enabled, if enabled { Class::Large } else { Class::Small }),
                count,
                0,
            )
            .await?;
        }
        // Recover the public openings used by the saved integer-program
        // fixture. Its program writes [7, inclusion_height] on every call.
        // Each reconstructed opening must match a currently unspent root.
        let mut objects = Vec::new();
        for height in 0..=chain.parent().height {
            let mut opening = integer_probe_opening();
            if height != 0 {
                opening.state =
                    noid_tx::experimental_object::integer_program::pack_state([7, height]);
            }
            objects.extend(
                chain
                    .slots_owned_by(opening.root())
                    .into_iter()
                    .map(|slot| (slot, opening.clone())),
            );
        }
        let calls = self
            .producer
            .v2()?
            .bank()
            .config()
            .class(Class::Small)
            .contract_slots();
        if objects.len() != calls {
            return Err(format!(
                "expected {calls} live fixture contracts, found {}",
                objects.len()
            ));
        }
        let mut batch = Batch::default();
        for (slot, opening) in objects {
            let [next] = chain.empty_slots()?;
            batch.object(chain, slot, next, &opening)?;
        }
        // Large is enabled but has a smaller call budget. The producer must
        // keep the more valuable complete small selection, beyond 16 calls.
        self.block(
            chain,
            "full_integer_calls_with_large_enabled",
            batch,
            (true, Class::Small),
            calls,
            calls,
        )
        .await?;
        Ok(())
    }
}
