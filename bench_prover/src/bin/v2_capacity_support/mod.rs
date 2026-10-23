// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_chain::consensus::{forks::ForkSchedule, AnchorInfo};
use noid_chain::{state::ChainState, Block, BlockHeader};
use noid_core::Block128;
use noid_gkr::{zk_authorization::ZkAuthorizationProof, OwnerAuthWitness};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
use noid_recursive::acceptance::history_step::{self as legacy, v2};
use noid_recursive::{ChainAccumulator, PreparedHistoryStepGhostAuthorization};
use noid_tx::{
    experimental_object::{ObjectOpening, ObjectRules},
    *,
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Instant,
};
pub mod banked;
mod boundaries;
mod legacy_tail;
mod payments;
pub mod production;
mod proof;
mod state;
pub use legacy_tail::measure as legacy_tail;
use state::*;

pub type Result<T> = std::result::Result<T, String>;
pub fn err(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}
fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}
fn secret(n: u8) -> SpendSecret {
    SpendSecret::from_bytes([n; 32])
}
fn address(n: u8) -> Address {
    derive_address(&secret(n))
}

// Process high-water RSS includes setup. It is deliberately labelled as such;
// phase-local receiver measurements must run in a separate process.
fn memory() -> serde_json::Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kb = |key: &str| -> Option<u64> {
        status
            .lines()
            .find(|line| line.starts_with(key))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    };
    json!({"rss_kib":kb("VmRSS:"), "process_peak_rss_kib":kb("VmHWM:")})
}

/// Compare research proofs to existing transport budgets without treating
/// byte-size compatibility as v2 P2P admission. The live metadata codec still
/// selects the v1/v1.1 formats; the candidate has its own versioned decoder.
fn wire_budget(
    runtime: &v2::V2Runtime,
    body_bytes: usize,
    terminal_bytes: usize,
) -> Result<serde_json::Value> {
    use noid_chain::consensus::wire_limits::{
        MAX_BLOCK_BYTES, MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES,
    };
    let shape_bound = v2::terminal_max_bytes(runtime).map_err(err)?;
    let payload = body_bytes
        .checked_add(terminal_bytes)
        .ok_or("wire length overflow")?;
    let bundle = payload
        .checked_add(noid_chain::accepted_block_bundle::ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES)
        .ok_or("bundle length overflow")?;
    Ok(json!({
        "terminal_shape_bound_bytes":shape_bound,
        "current_terminal_cap_bytes":MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES,
        "terminal_shape_fits_current_cap":shape_bound <= MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES,
        "terminal_encoded_fits_current_cap":terminal_bytes <= MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES,
        "current_block_cap_bytes":MAX_BLOCK_BYTES,
        "block_fits_current_cap":body_bytes <= MAX_BLOCK_BYTES,
        "body_plus_terminal_bytes":payload,
        "body_plus_terminal_fit_one_current_object_response":payload <= MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES,
        "accepted_bundle_framed_bytes":bundle,
        "bundle_fits_current_cap":bundle <= noid_chain::MAX_ACCEPTED_BLOCK_BUNDLE_BYTES,
        "production_v2_transport_qualified":false
    }))
}

pub struct Settings {
    pub pack: PathBuf,
    pub pin: [u8; 32],
    pub fixtures: PathBuf,
    pub output: PathBuf,
    pub config: v2::V2Config,
    pub samples: usize,
    pub freeze_only: bool,
    pub transition_only: bool,
    pub payments_only: bool,
}

/// A separate process for receiver measurements, with an externally supplied
/// candidate-bank pin. Matrix authentication and origin authentication are
/// measured as setup; every sample discharges the current full matrix claim.
pub fn verify_saved(args: &[String], with_state: bool) -> Result<()> {
    if args.len() != 7 {
        return Err("usage: noid_v2_capacity verify PACK_ROOT METADATA_PIN LEGACY_FIXTURES CANDIDATE_DIR BANK_PIN HEIGHT[,HEIGHT...] REPEATS".into());
    }
    if noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT != Some(5) {
        return Err("isolated-v1-1-testnet feature required".into());
    }
    let digest = |text: &str| -> Result<[u8; 32]> {
        hex::decode(text)
            .map_err(err)?
            .try_into()
            .map_err(|_| "pin length".into())
    };
    let heights: Vec<u64> = args[5]
        .split(',')
        .map(|s| s.parse().map_err(err))
        .collect::<Result<_>>()?;
    if heights.is_empty() || heights.len() > 8 {
        return Err("supply one to eight receiver heights".into());
    }
    let repeats: usize = args[6].parse().map_err(err)?;
    if !(1..=100).contains(&repeats) {
        return Err("repeats must be 1..=100".into());
    }
    let output = Path::new(&args[3]);
    let start = Instant::now();
    let runtime = proof::open_candidate(output, digest(&args[4])?)?;
    let legacy = proof::legacy_runtime(Path::new(&args[0]), digest(&args[1])?)?;
    let fork = runtime.bank().config().activation_height();
    let parent = Block::from_bytes(&proof::bounded(
        &Path::new(&args[2]).join(format!("h{:06}.block", fork - 1)),
        16 * 1024 * 1024,
    )?)
    .map_err(err)?;
    let epoch = noid_chain::consensus::genesis_header();
    if fork > noid_chain::consensus::params::TX_EPOCH_BLOCKS
        || heights.iter().any(|height| {
            *height < fork || *height >= noid_chain::consensus::params::TX_EPOCH_BLOCKS
        })
    {
        return Err("this short fixture receiver expects the genesis transaction epoch".into());
    }
    let legacy_bytes = proof::bounded(
        &Path::new(&args[2]).join(format!("h{:06}.terminal", fork - 1)),
        legacy::history_step_terminal_max_wire_bytes(&legacy).map_err(err)?,
    )?;
    let terminal = legacy::decode_history_step_terminal(&legacy, &legacy_bytes).map_err(err)?;
    let origin = v2::VerifiedV2Origin::from_legacy(
        &legacy,
        &terminal,
        &parent.header,
        &epoch,
        runtime.bank(),
    )
    .map_err(err)?;
    drop(terminal);
    drop(legacy);
    println!(
        "{}",
        json!({"phase":"receiver_setup","setup_ms":elapsed(start),"memory":memory(),
        "m":runtime.bank().config().outer_m(),"pages":runtime.bank().config().pages(),
        "max_live_inputs":runtime.bank().config().max_live_inputs(),
        "rayon_threads":rayon::current_num_threads(),
        "cpu_backend":noid_core::cpu::selected_backend().to_string()})
    );
    for height in heights {
        let bytes = proof::bounded(
            &output.join(format!("h{height:06}.terminal")),
            v2::terminal_max_bytes(&runtime).map_err(err)?,
        )?;
        let block = Block::from_bytes(&proof::bounded(
            &output.join(format!("h{height:06}.block")),
            16 * 1024 * 1024,
        )?)
        .map_err(err)?;
        println!(
            "{}",
            json!({"phase":"receiver_wire_budget", "height":height,
                "wire_budget":wire_budget(&runtime, block.to_bytes().len(), bytes.len())?,
                "production_bundle_codec_result":format!("{:?}",
                    noid_chain::AcceptedBlockBundle::try_from_parts(block.to_bytes(), bytes.clone())
                        .map(|_| ()))
            })
        );
        noid_chain::consensus::pow::validate_pow(&block.header).map_err(err)?;
        let parent_state = if with_state {
            // Authenticate the endpoint before replaying fixture bodies. The
            // replay checks every header link, native transition and root;
            // its final parent ID must be the one bound by this terminal.
            let terminal = v2::decode_terminal(&runtime, &bytes).map_err(err)?;
            let authenticated =
                v2::verify_terminal(&runtime, &origin, &terminal, &block.header, &epoch)
                    .map_err(err)?;
            let start = Instant::now();
            let chain = Chain::replay_for_receiver(
                Path::new(&args[2]),
                output,
                runtime.bank().config(),
                height - 1,
            )?;
            chain.check_native(&block, runtime.bank().config().schedule())?;
            let end = chain
                .accumulator
                .advance(chain.parent(), &block.header)
                .map_err(err)?;
            if noid_chain::hash_block_header(chain.parent()) != block.header.prev_block_hash
                || authenticated.accumulator() != &end
                || end.height != height
            {
                return Err("receiver State belongs to a different authenticated parent".into());
            }
            println!(
                "{}",
                json!({"phase":"receiver_state_setup","height":height,
                "replay_ms":elapsed(start),"memory":memory()})
            );
            Some(chain.state)
        } else {
            None
        };
        for sample in 0..=repeats {
            let start = Instant::now();
            let terminal = v2::decode_terminal(&runtime, &bytes).map_err(err)?;
            let accepted = v2::verify_terminal(&runtime, &origin, &terminal, &block.header, &epoch)
                .map_err(err)?;
            let verify_ms = elapsed(start);
            if accepted.accumulator().height != height {
                return Err("receiver accepted wrong height".into());
            }
            let state_apply_ms = if let Some(parent) = parent_state.as_ref() {
                let start = Instant::now();
                let mut trial = parent.clone();
                noid_chain::materialize_accepted_block_state(&mut trial, &block).map_err(err)?;
                Some(elapsed(start))
            } else {
                None
            };
            println!(
                "{}",
                json!({"phase":"receiver_verify","sample":sample,"warmup":sample==0,
            "height":height,"terminal_bytes":bytes.len(),"verify_ms":verify_ms,
            "state_apply_ms":state_apply_ms,"verify_apply_ms":state_apply_ms.map(|ms| ms + verify_ms),
            "memory":memory()})
            );
        }
    }
    Ok(())
}

pub fn measure<const PAGES: usize>(settings: Settings) -> Result<()> {
    let legacy_runtime = proof::legacy_runtime(&settings.pack, settings.pin)?;
    let (mut chain, legacy_tip) = Chain::load(&settings, &legacy_runtime)?;
    let ghost = noid_recursive::prepare_history_step_ghost_authorization_for_version(
        noid_gkr::ghost_tx::prove_selected_ghost_authorization_for_version(
            settings.config.authorization_version(),
        )
        .map_err(err)?,
        settings.config.authorization_version(),
    )
    .map_err(err)?;
    let (first, _) = chain.build(&[], settings.config.schedule())?;
    let (runtime, origin) = proof::freeze(
        &settings,
        &legacy_runtime,
        &legacy_tip,
        chain.parent(),
        &chain.epoch(),
        || chain.input::<PAGES>(&first, &Batch::default(), &ghost, settings.config),
    )?;
    drop(legacy_tip);
    drop(legacy_runtime);
    if settings.freeze_only {
        return Ok(());
    }
    let mut run = Run {
        runtime,
        origin,
        previous: None,
        checked_recursive_matrix: false,
        ghost,
        settings,
    };
    run.block::<PAGES>(&mut chain, "fork_empty", Batch::default())?;
    if run.settings.transition_only {
        for sample in 0..run.settings.samples {
            run.block::<PAGES>(
                &mut chain,
                &format!("transition_successor_{sample}"),
                Batch::default(),
            )?;
        }
        println!(
            "{}",
            json!({"complete":true,"mode":"transition","m":run.settings.config.outer_m(),
                "pages":PAGES,"successors":run.settings.samples,
                "tip":chain.parent().height,"memory":memory()})
        );
        return Ok(());
    }

    if run.settings.payments_only {
        return payments::measure::<PAGES>(&mut run, &mut chain);
    }

    let opening = integer_probe_opening();
    let mut ordinary = chain.ordinary_slots();
    let call_capacity = run.settings.config.contract_slots();
    while ordinary.len() < PAGES + call_capacity {
        let count = ordinary
            .len()
            .min(PAGES)
            .min(PAGES + call_capacity - ordinary.len());
        if count == 0 {
            return Err("legacy fixture has no ordinary funding notes".into());
        }
        let sources: Vec<_> = ordinary.drain(..count).collect();
        let mut batch = Batch::default();
        for source in sources {
            let fee = chain.fee(2);
            let amount = chain
                .input_slot(source)?
                .amount
                .checked_sub(fee)
                .ok_or("split balance")?;
            let slots = chain.empty_slots::<2>()?;
            let outputs = [
                TxOutput {
                    slot_index: slots[0],
                    amount: amount / 2,
                    owner: address(1),
                },
                TxOutput {
                    slot_index: slots[1],
                    amount: amount - amount / 2,
                    owner: address(1),
                },
            ];
            batch.ordinary(&chain, source, outputs, true)?;
            ordinary.extend(slots);
        }
        run.block::<PAGES>(&mut chain, "fund_ordinary", batch)?;
    }
    let mut batch = Batch::default();
    let mut objects = Vec::new();
    for source in ordinary.drain(..call_capacity) {
        let [slot] = chain.empty_slots()?;
        let amount = chain
            .input_slot(source)?
            .amount
            .checked_sub(chain.fee(1))
            .ok_or("object funding")?;
        batch.ordinary(
            &chain,
            source,
            [
                TxOutput {
                    slot_index: slot,
                    amount,
                    owner: opening.root(),
                },
                TxOutput::dummy(),
            ],
            false,
        )?;
        objects.push((slot, opening.clone()));
    }
    run.block::<PAGES>(&mut chain, "fund_objects", batch)?;
    for sample in 0..run.settings.samples {
        // Empty, light, fully filled and mixed cases all use the same pinned
        // complete recursive relation, including the configured call envelope.
        for (pages, calls) in [
            (0, 0),
            (4, 0),
            (PAGES, 0),
            (PAGES, 1.min(call_capacity)),
            (PAGES, 4.min(call_capacity)),
            (PAGES, call_capacity),
        ] {
            let mut batch = Batch::default();
            for object in objects.iter_mut().take(calls) {
                let [slot] = chain.empty_slots()?;
                let successor = batch.object(&chain, object.0, slot, &object.1)?;
                *object = (slot, successor);
            }
            for source in ordinary.iter_mut().take(pages - calls) {
                let [slot] = chain.empty_slots()?;
                let amount = chain
                    .input_slot(*source)?
                    .amount
                    .checked_sub(chain.fee(1))
                    .ok_or("payment balance")?;
                batch.ordinary(
                    &chain,
                    *source,
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
                *source = slot;
            }
            let label = format!("sample_{sample}_pages_{pages}_contracts_{calls}");
            run.block::<PAGES>(&mut chain, &label, batch)?;
        }
    }
    if run.settings.config.max_live_inputs()
        != noid_chain::consensus::params::block_class_spend_capacity(PAGES)
    {
        boundaries::measure::<PAGES>(&mut run, &mut chain)?;
    }
    println!(
        "{}",
        json!({"complete":true,"m":run.settings.config.outer_m(),"pages":PAGES,
        "samples":run.settings.samples,"tip":chain.parent().height,"memory":memory()})
    );
    Ok(())
}

fn integer_probe_opening() -> ObjectOpening {
    use noid_tx::experimental_object::integer_program::{
        Instruction, Opcode::*, Operand as O, Register as R, EMPTY_PROGRAM,
    };
    let mut program = EMPTY_PROGRAM;
    // Exercise checked arithmetic, authenticated height, scratch state and
    // assertions. Every reserved instruction is still present in the relation.
    for (step, instruction) in [
        Instruction::new(Move, R::State0, O::Immediate, O::Zero, 5),
        Instruction::new(Add, R::State0, O::State0, O::Immediate, 2),
        Instruction::new(Subtract, R::Scratch0, O::State0, O::One, 0),
        Instruction::new(Min, R::Scratch0, O::Scratch0, O::Immediate, 6),
        Instruction::new(Max, R::Scratch0, O::Scratch0, O::One, 0),
        Instruction::new(LessThan, R::Scratch1, O::Scratch0, O::State0, 0),
        Instruction::new(Equal, R::Scratch1, O::Scratch1, O::One, 0),
        Instruction::new(AssertEqual, R::State0, O::State0, O::Immediate, 7),
        Instruction::new(AssertLessOrEqual, R::State0, O::Scratch0, O::State0, 0),
        Instruction::new(Move, R::State1, O::Height, O::Zero, 0),
    ]
    .into_iter()
    .enumerate()
    {
        program[step] = instruction.to_fields();
    }
    let opening = ObjectOpening {
        program,
        state: Block128(3),
        claim_authority: address(2),
        recovery_authority: address(3),
        deadline: 10_000,
        claim_recipient: address(4),
        recovery_recipient: address(5),
        rules: ObjectRules {
            max_fee: u64::MAX,
            min_retained: 0,
            max_payout: u64::MAX,
            modes: 31,
        },
    };
    opening
}

struct Run {
    runtime: v2::V2Runtime,
    origin: v2::VerifiedV2Origin,
    previous: Option<v2::V2Terminal>,
    checked_recursive_matrix: bool,
    ghost: PreparedHistoryStepGhostAuthorization,
    settings: Settings,
}

impl Run {
    fn block<const PAGES: usize>(
        &mut self,
        chain: &mut Chain,
        label: &str,
        mut batch: Batch,
    ) -> Result<()> {
        batch.prove_authorizations(chain.parent().height + 1)?;
        let authorization_proof_bytes = batch
            .proofs
            .iter()
            .map(|proof| proof.to_bytes().map(|bytes| bytes.len()).map_err(err))
            .collect::<Result<Vec<_>>>()?;
        let start = Instant::now();
        let (mut block, construction_state) =
            chain.build(&batch.pages, self.settings.config.schedule())?;
        let template_ms = elapsed(start);
        drop(construction_state);
        let audit_full_payments = self.settings.payments_only
            && label.starts_with("payment_sample_")
            && batch.pages.len() == PAGES;
        if (batch.openings.len() == self.settings.config.contract_slots() || audit_full_payments)
            && !self.checked_recursive_matrix
        {
            let start = Instant::now();
            let frozen = v2::assemble_frozen(
                &self.runtime,
                self.origin.origin(),
                self.previous.as_ref(),
                chain.input::<PAGES>(&block, &batch, &self.ghost, self.settings.config)?,
            )
            .map_err(err)?;
            if frozen.matrix().statement_digest() != self.runtime.bank().matrix_digest()
                || frozen.block_vk() != self.runtime.parts().block_vk()
                || frozen.parent_vk() != self.runtime.parts().parent_vk()
                || !frozen.matrix().satisfies(frozen.witness())
            {
                return Err("full recursive block changed the matrix or is unsatisfied".into());
            }
            println!(
                "{}",
                json!({"phase":"full_recursive_matrix_audit","height":block.header.height,
                "pages":batch.pages.len(),"contracts":batch.openings.len(),"audit_ms":elapsed(start),"satisfied":true})
            );
            self.checked_recursive_matrix = true;
        }
        let start = Instant::now();
        let input = chain.input::<PAGES>(&block, &batch, &self.ghost, self.settings.config)?;
        let input_ms = elapsed(start);
        let start = Instant::now();
        let prepared = v2::prepare_for_pow(
            &self.runtime,
            self.origin.origin(),
            self.previous.as_ref(),
            input,
        )
        .map_err(err)?;
        let assembly_ms = elapsed(start);
        let start = Instant::now();
        block.header.nonce = mine(&block.header);
        let pow_ms = elapsed(start);
        let built = prepared
            .seal_nonce(&self.runtime, block.header.nonce)
            .map_err(err)?;
        let start = Instant::now();
        let proved = v2::prove_built(
            &self.runtime,
            &built,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .map_err(err)?;
        let prove_ms = elapsed(start);
        drop(built);
        let start = Instant::now();
        let bytes = v2::encode_terminal(&self.runtime, &proved).map_err(err)?;
        drop(proved);
        let encode_ms = elapsed(start);
        let start = Instant::now();
        let terminal = v2::decode_terminal(&self.runtime, &bytes).map_err(err)?;
        let accepted = v2::verify_terminal(
            &self.runtime,
            &self.origin,
            &terminal,
            &block.header,
            &chain.epoch(),
        )
        .map_err(err)?;
        let verify_ms = elapsed(start);
        let expected = chain
            .accumulator
            .advance(chain.parent(), &block.header)
            .map_err(err)?;
        if accepted.accumulator() != &expected {
            return Err("accepted boundary mismatch".into());
        }
        chain.check_native(&block, self.settings.config.schedule())?;
        let start = Instant::now();
        // Materialize only after the complete proof and scheduled native rules
        // have both accepted; a fixture never injects State slots.
        noid_chain::materialize_accepted_block_state(&mut chain.state, &block).map_err(err)?;
        let apply_ms = elapsed(start);
        let record = json!({"label":label, "height":block.header.height,"m":self.settings.config.outer_m(),
            "capacity":PAGES,"max_live_inputs":self.settings.config.max_live_inputs(),
            "contract_slots":self.settings.config.contract_slots(),
            "wire_budget":wire_budget(&self.runtime, block.to_bytes().len(), bytes.len())?,
            "wallet_authorization_proof_bytes_total":authorization_proof_bytes.iter().sum::<usize>(),
            "wallet_authorization_proof_bytes_max":authorization_proof_bytes.iter().copied().max(),
            "pages":batch.pages.len(),"contract_calls":batch.openings.len(),
            "live_inputs":batch.pages.iter().map(|p| p.body.live_input_count()).sum::<usize>(),
            "live_outputs":batch.pages.iter().map(|p| p.body.live_output_count()).sum::<usize>(),
            "touched_segments":block.transactions.iter().flat_map(|tx| {
                tx.body.live_inputs().map(|(_, input)| input.slot_index >> 16)
                    .chain(tx.body.live_outputs().map(|(_, output)| output.slot_index >> 16))
            }).collect::<BTreeSet<_>>().len(),
            "wallet_authorization_ms":batch.auth_ms,"wallet_batch_workers":batch.auth_workers,
            "fixture_template_ms":template_ms,
            "input_ms":input_ms,"assembly_ms":assembly_ms,"prove_ms":prove_ms,"pow_ms":pow_ms,
            "encode_ms":encode_ms,"verify_ms":verify_ms,"materialize_ms":apply_ms,
            "terminal_bytes":bytes.len(),"body_bytes":block.to_bytes().len(),"memory":memory()});
        println!("{record}");
        let stem = format!("h{:06}", block.header.height);
        std::fs::write(
            self.settings.output.join(format!("{stem}.terminal")),
            &bytes,
        )
        .map_err(err)?;
        std::fs::write(
            self.settings.output.join(format!("{stem}.block")),
            block.to_bytes(),
        )
        .map_err(err)?;
        std::fs::write(
            self.settings.output.join(format!("{stem}.json")),
            serde_json::to_vec_pretty(&record).map_err(err)?,
        )
        .map_err(err)?;
        if block.header.height <= self.settings.config.activation_height() + 1 {
            proof::audit_terminal(
                &self.runtime,
                &self.origin,
                &bytes,
                &block.header,
                &chain.epoch(),
            )?;
        }
        chain.accept(block, expected);
        self.previous = Some(terminal);
        Ok(())
    }
}

fn mine(header: &BlockHeader) -> u128 {
    let mut start = 0;
    loop {
        if let Some(nonce) = noid_chain::consensus::pow::search_pow(header, start, 65_536) {
            return nonce;
        }
        start += 65_536;
    }
}

#[derive(Default)]
struct Batch {
    pages: Vec<TxPage>,
    signers: Vec<u8>,
    proofs: Vec<ZkAuthorizationProof>,
    openings: Vec<ObjectOpening>,
    auth_ms: f64,
    auth_workers: usize,
}
impl Batch {
    fn prove_authorizations(&mut self, height: u64) -> Result<()> {
        use rayon::prelude::*;
        if self.pages.is_empty() {
            return Ok(());
        }
        self.auth_workers = 4.min(rayon::current_num_threads()).min(self.pages.len());
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.auth_workers)
            .build()
            .map_err(err)?;
        let start = Instant::now();
        self.proofs = pool.install(|| {
            self.pages
                .par_iter()
                .enumerate()
                .map(|(index, page)| {
                    let bundle = match self.openings.get(index) {
                        Some(opening) => {
                            noid_gkr::wallet_authorization::prove_experimental_object_authorization_for_version(
                                page,
                                opening,
                                height,
                                OwnerAuthWitness::new(secret(2)),
                                noid_chain::consensus::params::owner_authorization_version(height),
                            )
                        }
                        None => noid_gkr::wallet_authorization::prove_paged_spend_authorization_for_version(
                            std::slice::from_ref(page),
                            OwnerAuthWitness::new(secret(
                                self.signers.get(index).copied().unwrap_or(1),
                            )),
                            noid_chain::consensus::params::owner_authorization_version(height),
                        ),
                    }
                    .map_err(err)?;
                    Ok(bundle.proof)
                })
                .collect::<Result<Vec<_>>>()
        })?;
        self.auth_ms = elapsed(start);
        Ok(())
    }

    fn ordinary(
        &mut self,
        chain: &Chain,
        slot: u32,
        outputs: [TxOutput; 2],
        second: bool,
    ) -> Result<()> {
        self.ordinary_as(chain, slot, outputs, second, 1)
    }

    fn ordinary_as(
        &mut self,
        chain: &Chain,
        slot: u32,
        outputs: [TxOutput; 2],
        second: bool,
        signer: u8,
    ) -> Result<()> {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = chain.input_slot(slot)?;
        let page = TxPage::new(TxBody {
            epoch_anchor: chain.epoch_id(),
            fee: chain.fee(if second { 2 } else { 1 }),
            input_owner: address(signer),
            inputs,
            outputs,
            validity_bitmap: 1
                | output_bitmap_bit(0)
                | PAGED_SPEND_START_BIT
                | PAGED_SPEND_END_BIT
                | if second { output_bitmap_bit(1) } else { 0 },
            is_coinbase: false,
        })
        .map_err(err)?;
        self.pages.push(page);
        self.signers.resize(self.pages.len(), 1);
        *self.signers.last_mut().unwrap() = signer;
        Ok(())
    }
    fn object(
        &mut self,
        chain: &Chain,
        source: u32,
        slot: u32,
        opening: &ObjectOpening,
    ) -> Result<ObjectOpening> {
        if self.pages.len() != self.openings.len() {
            return Err("objects must form a prefix".into());
        }
        let height = chain.parent().height + 1;
        let page = opening
            .build_call(
                chain.input_slot(source)?,
                slot,
                chain.fee(1),
                chain.epoch_id(),
                height,
                false,
            )
            .map_err(err)?;
        let next = opening.successor(opening.execute(&page.body, height).map_err(err)?);
        self.pages.push(page);
        self.openings.push(opening.clone());
        Ok(next)
    }
}
