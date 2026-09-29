// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared benchmark fixtures for the canonical Tx8x2 and Field-R1CS paths.
//!
//! The `HistoryStep` pack generator builds its own one-shot freezing inputs.

use std::time::{Duration, Instant};

use noid_core::{Block128, CanonicalSerialize};
use noid_gkr::zk_authorization::ZkAuthorizationProof;
use noid_gkr::{
    prove_paged_spend_authorization, prove_v2_contract_controller_authorization,
    prove_wallet_authorization, verify_wallet_authorization_proof, OwnerAuthWitness,
    WalletAuthorizationBundle,
};
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, DomainTag};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret, TxBodyHash};
use noid_tx::body_hash::{
    body_hash_leaves, TX8X2_LEAF_EPOCH_ANCHOR, TX8X2_LEAF_FEE, TX8X2_LEAF_FLAGS,
    TX8X2_LEAF_OUTPUT0_DATA, TX8X2_LEAF_OUTPUT1_DATA, TX8X2_LEAF_OUTPUT1_OWNER,
};
use noid_tx::{
    hash_paged_spend, output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TxPage,
    PAGED_SPEND_CONTRACT_BIT, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT, PAGED_SPEND_TERMINAL_BIT,
    TX_INPUTS, TX_OUTPUTS,
};

pub const BENCH_LOG_SLOTS: u32 = 24;
pub const B255_EIGHT_INPUT_TXS: usize = 85;
pub const B255_TWO_INPUT_TXS: usize = 170;

#[derive(Clone)]
pub struct BenchScenario {
    pub label: &'static str,
    pub desc: String,
    pub body: TxBody,
    /// Public deterministic seed used to recreate a fresh, consuming wallet
    /// proving authority for each sample.
    pub spend_secret_seed: u128,
}

impl BenchScenario {
    pub fn spend_secret(&self) -> SpendSecret {
        mk_secret(self.spend_secret_seed)
    }
}

#[derive(Clone)]
pub struct MinimalTxFixture {
    pub scenario: BenchScenario,
    pub auth_proof: ZkAuthorizationProof,
}

pub struct WalletBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof: ZkAuthorizationProof,
}

pub fn fmt_ms(duration: Duration) -> String {
    let milliseconds = duration.as_secs_f64() * 1_000.0;
    if milliseconds >= 1_000.0 {
        format!("{:>8.2} s ", milliseconds / 1_000.0)
    } else {
        format!("{:>8.2} ms", milliseconds)
    }
}

pub fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>8.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>8.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>8} B ", bytes)
    }
}

pub fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

pub fn time_once<F, R>(operation: F) -> (Duration, R)
where
    F: FnOnce() -> R,
{
    let started = Instant::now();
    let value = operation();
    (started.elapsed(), value)
}

pub fn time_median<F>(samples: usize, mut operation: F) -> Duration
where
    F: FnMut(),
{
    assert!(samples > 0);
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        operation();
        timings.push(started.elapsed());
    }
    median(timings)
}

/// Representative Field-R1CS shape used by prover microbenchmarks.
pub fn poseidon_chain_field_instance(
    chain: usize,
) -> (
    noid_ivc_prover::field_r1cs::FieldR1cs,
    Vec<noid_ivc_prover::field::F128>,
) {
    use noid_ivc_prover::field_circuit::{flat_const, poseidon2b_permute, LinExpr};
    use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, STATE_SIZE};
    use noid_recursive::acceptance::trace::FieldR1csBuilder;

    let seed: [Block128; STATE_SIZE] =
        std::array::from_fn(|index| Block128(0x1234_5678_9abc_def0 + index as u128));
    let mut expected = seed;
    for _ in 0..chain {
        Poseidon2bPermutation.permute_mut(&mut expected);
    }
    let mut builder = FieldR1csBuilder::new();
    let mut state: [LinExpr; STATE_SIZE] = std::array::from_fn(|index| {
        LinExpr::from_wire(builder.alloc_f128(flat_const(seed[index].0)))
    });
    for _ in 0..chain {
        state = poseidon2b_permute(&mut builder, state);
    }
    for lane in &state {
        let value = lane.eval(builder.values());
        builder.pin_f128(lane, value);
    }
    builder.build()
}

pub fn mk_secret(seed: u128) -> SpendSecret {
    let low = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_A5A5_A5A5_A5A5;
    let high = seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&low.to_le_bytes());
    bytes[16..].copy_from_slice(&high.to_le_bytes());
    SpendSecret::from_bytes(bytes)
}

/// Build one canonical Tx8x2 scenario with `1..=8` live inputs and `1..=2`
/// live outputs. All inputs share the address derived from one secret.
pub fn tx8x2_scenario(
    label: &'static str,
    input_count: usize,
    output_count: usize,
    slot_base: u32,
    seed: u128,
) -> BenchScenario {
    assert!((1..=TX_INPUTS).contains(&input_count));
    assert!((1..=TX_OUTPUTS).contains(&output_count));

    let spend_secret = mk_secret(seed);
    let input_owner = derive_address(&spend_secret);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    let mut input_sum = 0u64;
    let mut validity_bitmap = 0u16;
    for (index, input) in inputs.iter_mut().enumerate().take(input_count) {
        let amount = 100_000 + (input_count - index) as u64 * 10_000;
        input_sum = input_sum.checked_add(amount).expect("benchmark input sum");
        *input = TxInput {
            slot_index: slot_base + index as u32,
            amount,
            creation_id: 0,
        };
        validity_bitmap |= 1 << index;
    }

    let fee = 5_000 + (input_count + output_count) as u64 * 500;
    let spendable = input_sum
        .checked_sub(fee)
        .expect("benchmark fee fits inputs");
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    let mut remaining = spendable;
    for (index, output) in outputs.iter_mut().enumerate().take(output_count) {
        let amount = if index + 1 == output_count {
            remaining
        } else {
            spendable / output_count as u64
        };
        remaining -= amount;
        *output = TxOutput {
            slot_index: slot_base + 1_000 + index as u32,
            amount,
            owner: derive_address(&mk_secret(seed + 0x10_000 + index as u128)),
        };
        validity_bitmap |= output_bitmap_bit(index);
    }

    let body = TxBody {
        epoch_anchor: [0xAA; 32],
        fee,
        input_owner,
        inputs,
        outputs,
        validity_bitmap,
        is_coinbase: false,
    };
    body.validate_canonical().expect("canonical Tx8x2 fixture");
    BenchScenario {
        label,
        desc: format!("Tx8x2: {input_count} inputs / {output_count} outputs"),
        body,
        spend_secret_seed: seed,
    }
}

/// Build the legal saturation body set for one HistoryStep current tier.
pub fn legal_block_scenarios(
    label: &'static str,
    user_txs: usize,
    seed_base: u128,
) -> Vec<BenchScenario> {
    assert!(noid_chain::consensus::params::BLOCK_PAGE_CLASS_TIERS.contains(&user_txs));
    if user_txs == noid_chain::consensus::params::BLOCK_MAX_USER_PAGES {
        return b255_saturation_scenarios(label, seed_base);
    }
    (0..user_txs)
        .map(|index| {
            tx8x2_scenario(
                label,
                TX_INPUTS,
                TX_OUTPUTS,
                (index * 2_048) as u32,
                seed_base + index as u128,
            )
        })
        .collect()
}

/// Legal 255-user saturation foundation with the consensus maximum 1020
/// inputs and 510 outputs spread across all depth-24 state segments.
pub fn b255_saturation_scenarios(label: &'static str, seed_base: u128) -> Vec<BenchScenario> {
    const INPUT_PAIRS: [[usize; 2]; 8] = [
        [0, 7],
        [1, 6],
        [2, 5],
        [3, 4],
        [0, 5],
        [1, 7],
        [2, 6],
        [3, 7],
    ];

    let coinbase_slot = (1u32 << BENCH_LOG_SLOTS) - 1;
    let mut touched = maximally_dispersed_b255_touched_slots();
    let coinbase_position = touched
        .iter()
        .position(|slot| *slot == coinbase_slot)
        .expect("fixture reserves the coinbase slot");
    touched.swap_remove(coinbase_position);

    let mut cursor = 0usize;
    let mut next_creation_id = 1u64;
    let mut scenarios = Vec::with_capacity(255);
    for tx_index in 0..255 {
        let input_count = if tx_index < B255_EIGHT_INPUT_TXS {
            TX_INPUTS
        } else {
            2
        };
        let positions: Vec<_> = if input_count == TX_INPUTS {
            (0..TX_INPUTS).collect()
        } else {
            INPUT_PAIRS[(tx_index - B255_EIGHT_INPUT_TXS) % INPUT_PAIRS.len()].to_vec()
        };
        let input_slots = &touched[cursor..cursor + input_count];
        cursor += input_count;
        let output_slots: [u32; TX_OUTPUTS] = touched[cursor..cursor + TX_OUTPUTS]
            .try_into()
            .expect("two output slots");
        cursor += TX_OUTPUTS;
        scenarios.push(tx8x2_scenario_with_layout(
            label,
            &positions,
            input_slots,
            output_slots,
            next_creation_id,
            seed_base + tx_index as u128,
        ));
        next_creation_id += input_count as u64;
    }
    assert_eq!(cursor, touched.len());
    assert_eq!(next_creation_id - 1, 1_020);
    scenarios
}

fn maximally_dispersed_b255_touched_slots() -> Vec<u32> {
    let mut slots = Vec::with_capacity(noid_chain::consensus::params::BLOCK_MAX_ACTIONS);
    for segment_rank in 0..noid_chain::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS {
        let segment = (segment_rank as u32).reverse_bits() >> 24;
        let local_count = if segment_rank < 251 { 6 } else { 5 };
        for local_rank in 0..local_count {
            let mut local = (local_rank as u32).reverse_bits() >> 16;
            if segment == 0 || segment == u8::MAX as u32 {
                local ^= u16::MAX as u32;
            }
            slots.push((segment << noid_chain::consensus::params::LOG_SEGMENT_SIZE) | local);
        }
    }
    assert_eq!(
        slots.len(),
        noid_chain::consensus::params::BLOCK_MAX_ACTIONS
    );
    slots
}

fn tx8x2_scenario_with_layout(
    label: &'static str,
    input_positions: &[usize],
    input_slots: &[u32],
    output_slots: [u32; TX_OUTPUTS],
    first_creation_id: u64,
    seed: u128,
) -> BenchScenario {
    assert_eq!(input_positions.len(), input_slots.len());
    let spend_secret = mk_secret(seed);
    let input_owner = derive_address(&spend_secret);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    let mut validity_bitmap = 0u16;
    let mut input_sum = 0u64;
    for (logical_index, (&position, &slot_index)) in
        input_positions.iter().zip(input_slots).enumerate()
    {
        let amount = 1_000_000 + (logical_index as u64 + 1) * 10_000 + seed as u64 % 997;
        input_sum = input_sum.checked_add(amount).expect("fixture input sum");
        inputs[position] = TxInput {
            slot_index,
            amount,
            creation_id: first_creation_id + logical_index as u64,
        };
        validity_bitmap |= 1 << position;
    }
    let fee = noid_chain::consensus::fees::fee_breakdown(
        input_slots.len() as u64,
        TX_OUTPUTS as u64,
        noid_chain::consensus::params::BLOCK_MAX_LIVE_INPUTS as u64,
        BENCH_LOG_SLOTS,
    )
    .required_total;
    let spendable = input_sum.checked_sub(fee).expect("fixture fee fits inputs");
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    let first_output = spendable / 2;
    outputs[0] = TxOutput {
        slot_index: output_slots[0],
        amount: first_output,
        owner: derive_address(&mk_secret(seed + 0x10_000)),
    };
    outputs[1] = TxOutput {
        slot_index: output_slots[1],
        amount: spendable - first_output,
        owner: derive_address(&mk_secret(seed + 0x20_000)),
    };
    validity_bitmap |= output_bitmap_bit(0) | output_bitmap_bit(1);
    let body = TxBody {
        epoch_anchor: [0xAA; 32],
        fee,
        input_owner,
        inputs,
        outputs,
        validity_bitmap,
        is_coinbase: false,
    };
    body.validate_canonical().expect("canonical B255 fixture");
    BenchScenario {
        label,
        desc: format!(
            "B255 saturation Tx8x2: {} inputs / {} outputs",
            input_slots.len(),
            TX_OUTPUTS
        ),
        body,
        spend_secret_seed: seed,
    }
}

pub fn state_shrinking_scenario(
    label: &'static str,
    input_count: usize,
    slot_base: u32,
    seed: u128,
) -> BenchScenario {
    let mut scenario = tx8x2_scenario(label, input_count, 1, slot_base, seed);
    scenario.desc = format!("Tx8x2 state shrink: {input_count} inputs / 1 output");
    scenario
}

pub fn minimal_tx_fixture(scenario: BenchScenario) -> MinimalTxFixture {
    let proof = prove_wallet_authorization(
        &scenario.body,
        OwnerAuthWitness::new(scenario.spend_secret()),
    )
    .expect("wallet authorization fixture")
    .proof;
    MinimalTxFixture {
        scenario,
        auth_proof: proof,
    }
}

pub fn prove_wallet(fixture: &MinimalTxFixture, samples: usize) -> WalletBench {
    let prove_time = time_median(samples, || {
        prove_wallet_authorization(
            &fixture.scenario.body,
            OwnerAuthWitness::new(fixture.scenario.spend_secret()),
        )
        .expect("prove wallet authorization");
    });
    let proof = prove_wallet_authorization(
        &fixture.scenario.body,
        OwnerAuthWitness::new(fixture.scenario.spend_secret()),
    )
    .expect("prove wallet authorization")
    .proof;
    let verify_time = time_median(samples, || {
        verify_wallet_authorization_proof(&fixture.scenario.body, &proof)
            .expect("verify wallet authorization");
    });
    WalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn authorization_size(proof: &ZkAuthorizationProof) -> usize {
    proof.to_bytes().expect("encode authorization proof").len()
}

pub fn wallet_bundle_size(proof: &ZkAuthorizationProof) -> usize {
    WalletAuthorizationBundle {
        proof: proof.clone(),
    }
    .to_bytes()
    .expect("encode wallet bundle")
    .len()
}

pub fn live_counts(body: &TxBody) -> (usize, usize) {
    (body.live_input_count(), body.live_output_count())
}

pub fn block_tx_hash_body(body: &TxBody) -> TxBodyHash {
    body.txid()
}

/// Native user counts used by the release freezer's honest backbone.
///
/// B25 blocks grow a spendable pool geometrically; the final 26-page block
/// establishes the B255 parent boundary. Every block starts at canonical
/// genesis ancestry and is mined, checked and materialized through the
/// production state transition.
pub const HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS: [usize; 7] = [0, 1, 3, 7, 15, 25, 26];

/// One honest current-block member for each fixed HistoryStep tier.
pub const HISTORY_STEP_FREEZER_FORK_USER_COUNTS: [usize; 2] = [25, 26];

#[derive(Clone)]
struct TrackedSpendable {
    slot_index: u32,
    spend_secret_seed: u128,
}

impl TrackedSpendable {
    fn spend_secret(&self) -> SpendSecret {
        mk_secret(self.spend_secret_seed)
    }
}

const V2_RESEARCH_PROGRAM_STEPS: usize = noid_tx::experimental_object::PROGRAM_STEPS;
const V2_RESEARCH_CODE_DOMAIN: DomainTag = DomainTag::new(b"CNTCODE_");
const V2_RESEARCH_POLICY_DOMAIN: DomainTag = DomainTag::new(b"CNTPOL__");
const V2_RESEARCH_OBJECT_DOMAIN: DomainTag = DomainTag::new(b"CNTOBJ__");

#[derive(Clone)]
struct V2ResearchObject {
    program: [[Block128; 2]; V2_RESEARCH_PROGRAM_STEPS],
    current: Block128,
    controller_seed: u128,
    controller: [Block128; 2],
    refund_authority_seed: u128,
    refund_authority: [Block128; 2],
    old_root: Address,
    deadline: u64,
    claim_recipient: [Block128; 2],
    refund_recipient: [Block128; 2],
}

/// Deliberately invalid research cases used to demonstrate that each new
/// contract boundary is enforced rather than merely carried as witness data.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2ResearchMutation {
    None,
    InvalidOpcodeOpening,
    WrongNextOpening,
    WrongContextOpening,
    WrongTerminalRecipient,
    WrongBranchAuthorization,
}

fn v2_digest_fields(bytes: [u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(bytes[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(bytes[16..].try_into().unwrap())),
    ]
}

fn v2_address(fields: [Block128; 2]) -> Address {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&fields[0].to_bytes());
    bytes[16..].copy_from_slice(&fields[1].to_bytes());
    Address(bytes)
}

fn v2_code_digest(program: &[[Block128; 2]; V2_RESEARCH_PROGRAM_STEPS]) -> [Block128; 2] {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(V2_RESEARCH_CODE_DOMAIN));
    for instruction in program {
        sponge.absorb_pair(instruction[0], instruction[1]);
    }
    v2_digest_fields(sponge.finalize_no_pad())
}

fn v2_object_root(
    program: &[[Block128; 2]; V2_RESEARCH_PROGRAM_STEPS],
    state: Block128,
    controller: [Block128; 2],
    refund_authority: [Block128; 2],
    deadline: u64,
    claim_recipient: [Block128; 2],
    refund_recipient: [Block128; 2],
) -> Address {
    let code = v2_code_digest(program);
    let mut policy = Poseidon2bSponge::with_iv(capacity_iv(V2_RESEARCH_POLICY_DOMAIN));
    policy.absorb_pair(code[0], code[1]);
    policy.absorb_pair(Block128::from(deadline as u128), controller[0]);
    policy.absorb_pair(controller[1], refund_authority[0]);
    policy.absorb_pair(refund_authority[1], claim_recipient[0]);
    policy.absorb_pair(claim_recipient[1], refund_recipient[0]);
    policy.absorb_pair(
        refund_recipient[1],
        Block128::from(noid_tx::experimental_object::OBJECT_VERSION as u128),
    );
    let rules = v2_research_rules().fields();
    policy.absorb_pair(rules[0], rules[1]);
    policy.absorb_pair(rules[2], rules[3]);
    let policy = v2_digest_fields(policy.finalize_no_pad());
    let mut object = Poseidon2bSponge::with_iv(capacity_iv(V2_RESEARCH_OBJECT_DOMAIN));
    object.absorb_pair(policy[0], policy[1]);
    object.absorb_pair(state, Block128::from(0u128));
    Address(object.finalize_no_pad())
}

fn v2_contract_context(
    body: &TxBody,
) -> [Block128; noid_tx::experimental_object::BODY_CONTEXT_FIELDS] {
    let leaves = body_hash_leaves(body);
    [
        leaves[TX8X2_LEAF_EPOCH_ANCHOR][0],
        leaves[TX8X2_LEAF_EPOCH_ANCHOR][1],
        leaves[TX8X2_LEAF_FEE][0],
        leaves[TX8X2_LEAF_OUTPUT0_DATA][1],
        leaves[TX8X2_LEAF_OUTPUT1_DATA][1],
        leaves[TX8X2_LEAF_OUTPUT1_OWNER][0],
        leaves[TX8X2_LEAF_OUTPUT1_OWNER][1],
        leaves[TX8X2_LEAF_FLAGS][0],
    ]
}

fn v2_execute_program(
    state: Block128,
    program: &[[Block128; 2]; V2_RESEARCH_PROGRAM_STEPS],
    body: &TxBody,
    height: u64,
    deadline: u64,
) -> Block128 {
    use noid_tx::experimental_object::integer_program::{execute, Context};
    execute(program, state, Context::from_body(body, height, deadline))
        .expect("valid integer research program")
}

fn v2_research_object(seed: u128, index: usize, parent_height: u64) -> V2ResearchObject {
    let controller_seed = seed.wrapping_add(0xC017_0000).wrapping_add(index as u128);
    let controller = derive_address(&mk_secret(controller_seed)).as_fields();
    let refund_authority_seed = seed.wrapping_add(0xBEF0_0000).wrapping_add(index as u128);
    let refund_authority = derive_address(&mk_secret(refund_authority_seed)).as_fields();
    let program = std::array::from_fn(|step| {
        use noid_tx::experimental_object::integer_program::{
            Instruction, Opcode as Op, Operand as Arg, Register as Reg,
        };
        let immediate = seed
            .wrapping_add(0xA000_0000)
            .wrapping_add((index as u128) << 8)
            .wrapping_add(step as u128 + 1) as u64
            & ((1u64 << 48) - 1);
        match step % 6 {
            0 => Instruction::new(Op::Move, Reg::State0, Arg::Immediate, Arg::Zero, immediate),
            1 => Instruction::new(Op::Add, Reg::State0, Arg::State0, Arg::One, 0),
            2 => Instruction::new(Op::Move, Reg::State1, Arg::Height, Arg::Zero, 0),
            3 => Instruction::new(Op::Max, Reg::State0, Arg::State0, Arg::Payout, 0),
            4 => Instruction::new(
                Op::Equal,
                Reg::Scratch0,
                Arg::State0,
                Arg::Immediate,
                immediate,
            ),
            _ => Instruction::new(Op::Min, Reg::State1, Arg::State1, Arg::InputAmount, 0),
        }
        .to_fields()
    });
    let current = Block128::from(
        seed.wrapping_add(0x5700_0000)
            .wrapping_add(index as u128 + 1),
    );
    let claim_recipient = derive_address(&mk_secret(
        seed.wrapping_add(0xC1A1_0000).wrapping_add(index as u128),
    ))
    .as_fields();
    let refund_recipient = derive_address(&mk_secret(
        seed.wrapping_add(0xBACC_0000).wrapping_add(index as u128),
    ))
    .as_fields();
    let child_height = parent_height + 1;
    let deadline = if index % 2 == 0 {
        child_height + 1
    } else {
        child_height
    };
    let old_root = v2_object_root(
        &program,
        current,
        controller,
        refund_authority,
        deadline,
        claim_recipient,
        refund_recipient,
    );
    V2ResearchObject {
        program,
        current,
        controller_seed,
        controller,
        refund_authority_seed,
        refund_authority,
        old_root,
        deadline,
        claim_recipient,
        refund_recipient,
    }
}

#[derive(Clone)]
struct HistoryStepFixtureCheckpoint {
    parent_header: noid_chain::BlockHeader,
    tx_epoch_anchor_header: noid_chain::BlockHeader,
    parent_state: noid_chain::state::ChainState,
    start_accumulator: noid_recursive::ChainAccumulator,
    previous_timestamps: Vec<u64>,
    finalized_active_counts: Vec<u64>,
    asert_anchor: noid_chain::consensus::AnchorInfo,
    spendables: Vec<TrackedSpendable>,
    output_slot_cursor: u32,
}

/// A mined, fully prepared release-freezer witness for one HistoryStep input.
///
/// The start/end accumulators are owned beside the one-shot witness so the
/// freezer can consume the input immediately without retaining borrowed
/// chain state or reconstructing any boundary.
pub struct PreparedHistoryStepTierFixture<const TIER: usize> {
    witness: noid_block::PreparedHistoryStepInputWitness<TIER>,
    nonce: u128,
    start_accumulator: noid_recursive::ChainAccumulator,
    end_accumulator: noid_recursive::ChainAccumulator,
    input_preparation: Duration,
    user_pages: usize,
}

impl<const TIER: usize> PreparedHistoryStepTierFixture<TIER> {
    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn start_accumulator(&self) -> &noid_recursive::ChainAccumulator {
        &self.start_accumulator
    }

    pub fn end_accumulator(&self) -> &noid_recursive::ChainAccumulator {
        &self.end_accumulator
    }

    /// Node-side preparation after the block template and wallet proofs exist:
    /// bounded payload accounting, authorization decoding, page-class checks
    /// and construction of the exact native HistoryStep witness components.
    pub fn input_preparation(&self) -> Duration {
        self.input_preparation
    }

    pub fn user_pages(&self) -> usize {
        self.user_pages
    }

    pub fn into_parts(
        self,
    ) -> (
        noid_block::PreparedHistoryStepInputWitness<TIER>,
        u128,
        noid_recursive::ChainAccumulator,
        noid_recursive::ChainAccumulator,
    ) {
        (
            self.witness,
            self.nonce,
            self.start_accumulator,
            self.end_accumulator,
        )
    }

    fn into_history_step_input(
        self,
    ) -> Result<noid_recursive::HistoryStepBlockInput<TIER>, String> {
        let (witness, nonce, start, end) = self.into_parts();
        witness
            .finish(nonce, &start, &end)
            .map(|(_, input)| input)
            .map_err(|error| format!("finish honest B{TIER} HistoryStep witness: {error}"))
    }
}

/// Heterogeneous streaming item used while the freezer proves the backbone.
pub enum PreparedHistoryStepBackboneInput {
    B25(PreparedHistoryStepTierFixture<25>),
    B255(PreparedHistoryStepTierFixture<255>),
}

/// One backbone item and the parent-tier checkpoint established after it.
pub struct HonestHistoryStepBackboneStep {
    pub input: PreparedHistoryStepBackboneInput,
    pub capture_parent_slot: Option<usize>,
}

struct BuiltFixtureChild<const TIER: usize> {
    prepared: PreparedHistoryStepTierFixture<TIER>,
    sealed_block: noid_chain::Block,
    next_spendables: Vec<TrackedSpendable>,
    next_output_slot_cursor: u32,
}

/// Deterministic, resettable source of real release-freezer witnesses.
///
/// A pass first streams the canonical-genesis backbone. Once both parent
/// checkpoints exist, each class method forks a real child from the exact
/// checkpoint selected by `class_id.parent_slot()`. Only the currently
/// requested witness is materialized.
pub struct HonestHistoryStepFixtureProvider {
    seed: u128,
    ghost: noid_recursive::PreparedHistoryStepGhostAuthorization,
    authorization_proofs:
        std::cell::RefCell<std::collections::HashMap<TxBodyHash, ZkAuthorizationProof>>,
    mined_nonces: std::cell::RefCell<std::collections::HashMap<[u8; 32], u128>>,
    backbone_index: usize,
    live: HistoryStepFixtureCheckpoint,
    checkpoints:
        [Option<HistoryStepFixtureCheckpoint>; noid_recursive::HISTORY_STEP_TIER_SLOT_COUNT],
}

impl HonestHistoryStepFixtureProvider {
    pub fn new(seed: u128) -> Result<Self, String> {
        let ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
            .map_err(|error| format!("prove canonical ghost authorization: {error}"))?;
        let ghost = noid_recursive::prepare_history_step_ghost_authorization(ghost)
            .map_err(|error| format!("prepare canonical ghost authorization: {error}"))?;
        let live = genesis_fixture_checkpoint();
        Ok(Self {
            seed,
            ghost,
            authorization_proofs: std::cell::RefCell::new(std::collections::HashMap::new()),
            mined_nonces: std::cell::RefCell::new(std::collections::HashMap::new()),
            backbone_index: 0,
            live,
            checkpoints: std::array::from_fn(|_| None),
        })
    }

    /// Start a fresh deterministic freezer pass at the canonical genesis
    /// boundary. This drops all previous state checkpoints and witnesses.
    pub fn reset_backbone(&mut self) {
        self.backbone_index = 0;
        self.live = genesis_fixture_checkpoint();
        self.checkpoints = std::array::from_fn(|_| None);
    }

    pub fn next_backbone(
        &mut self,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<Option<HonestHistoryStepBackboneStep>, String> {
        if self.backbone_index == HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS.len() {
            return Ok(None);
        }
        if &self.live.start_accumulator != expected_start {
            return Err("freezer backbone start does not match the honest native boundary".into());
        }

        let step = self.backbone_index;
        let user_count = HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS[step];
        let capture_parent_slot = match step {
            5 => Some(0),
            6 => Some(1),
            _ => None,
        };
        let input = match noid_chain::consensus::params::block_page_class_tier(user_count) {
            Some(25) => self
                .build_child::<25>(user_count, step as u128)?
                .map_into(&mut self.live)?,
            Some(255) => self
                .build_child::<255>(user_count, step as u128)?
                .map_into(&mut self.live)?,
            _ => return Err("backbone user count does not select a canonical tier".into()),
        };

        self.backbone_index += 1;
        if let Some(parent_slot) = capture_parent_slot {
            self.checkpoints[parent_slot] = Some(self.live.clone());
        }
        Ok(Some(HonestHistoryStepBackboneStep {
            input,
            capture_parent_slot,
        }))
    }

    pub fn b25(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<PreparedHistoryStepTierFixture<25>, String> {
        self.fork::<25>(
            class_id,
            expected_start,
            HISTORY_STEP_FREEZER_FORK_USER_COUNTS[0],
        )
    }

    /// Coinbase-only B25 child used to calibrate the benchmark against the
    /// default mining path. The recursive proof shape remains the complete
    /// B25 class shape.
    pub fn b25_coinbase_only(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<PreparedHistoryStepTierFixture<25>, String> {
        self.fork::<25>(class_id, expected_start, 0)
    }

    pub fn b255(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<PreparedHistoryStepTierFixture<255>, String> {
        self.fork::<255>(
            class_id,
            expected_start,
            HISTORY_STEP_FREEZER_FORK_USER_COUNTS[1],
        )
    }

    pub fn parent_accumulator(
        &self,
        parent_slot: usize,
    ) -> Option<&noid_recursive::ChainAccumulator> {
        self.checkpoints
            .get(parent_slot)?
            .as_ref()
            .map(|checkpoint| &checkpoint.start_accumulator)
    }

    /// Build a natively checked saturated B25 child whose first `contract_count`
    /// logical transactions consume proof-native object roots. The parent
    /// State is a deterministic research boundary derived from the honest B25
    /// checkpoint; no new parent terminal is claimed or required by the
    /// direct-block matrix experiment.
    #[doc(hidden)]
    pub fn v2_research_b25_input(
        &self,
        contract_count: usize,
    ) -> Result<noid_recursive::HistoryStepBlockInput<25>, String> {
        self.v2_research_input::<25>(contract_count, V2ResearchMutation::None, 0, 25)
    }

    #[doc(hidden)]
    pub fn v2_research_b25_input_with_mutation(
        &self,
        contract_count: usize,
        mutation: V2ResearchMutation,
    ) -> Result<noid_recursive::HistoryStepBlockInput<25>, String> {
        self.v2_research_input::<25>(contract_count, mutation, 0, 25)
    }

    #[doc(hidden)]
    pub fn v2_research_b255_input(
        &self,
        contract_count: usize,
    ) -> Result<noid_recursive::HistoryStepBlockInput<255>, String> {
        self.v2_research_input::<255>(contract_count, V2ResearchMutation::None, 1, 26)
    }

    fn v2_research_input<const TIER: usize>(
        &self,
        contract_count: usize,
        mutation: V2ResearchMutation,
        parent_slot: usize,
        user_count: usize,
    ) -> Result<noid_recursive::HistoryStepBlockInput<TIER>, String> {
        if contract_count > noid_recursive::V2_CONTRACT_SLOTS {
            return Err(format!(
                "research B{TIER} supports at most {} contract calls",
                noid_recursive::V2_CONTRACT_SLOTS
            ));
        }
        let needs_terminal = matches!(
            mutation,
            V2ResearchMutation::WrongTerminalRecipient
                | V2ResearchMutation::WrongBranchAuthorization
        );
        if (mutation != V2ResearchMutation::None && contract_count == 0)
            || (needs_terminal && contract_count < 2)
        {
            return Err("research mutation requires a matching live contract slot".into());
        }
        let mut checkpoint = self.checkpoints[parent_slot]
            .as_ref()
            .ok_or_else(|| format!("honest B{TIER} parent checkpoint has not been built"))?
            .clone();
        if checkpoint.spendables.len() < user_count {
            return Err(format!("honest B{TIER} parent has too few spendables"));
        }

        let objects = (0..contract_count)
            .map(|index| v2_research_object(self.seed, index, checkpoint.parent_header.height))
            .collect::<Vec<_>>();
        for (source, object) in checkpoint
            .spendables
            .iter()
            .take(contract_count)
            .zip(&objects)
        {
            let old = checkpoint.parent_state.state.slot(source.slot_index);
            if old.is_empty() {
                return Err("research object source slot is empty".into());
            }
            checkpoint
                .parent_state
                .state
                .set_slot(
                    source.slot_index,
                    noid_chain::SlotValue::with_owner_fields(
                        old.amount(),
                        old.creation_id(),
                        object.old_root.as_fields(),
                    ),
                )
                .map_err(|error| format!("install research object: {error:?}"))?;
        }
        if contract_count != 0 {
            let root = checkpoint
                .parent_state
                .try_state_root()
                .map_err(|error| format!("seal research parent State: {error}"))?;
            checkpoint.parent_header.state_root = root;
            checkpoint.start_accumulator.state_root = root;
            checkpoint.start_accumulator.tip_semantic_id =
                noid_chain::block_header::semantic_header_id(&checkpoint.parent_header);
        }

        let timestamp = checkpoint
            .parent_header
            .timestamp
            .checked_add(noid_chain::consensus::params::BLOCK_TIME)
            .ok_or_else(|| "research timestamp overflow".to_owned())?;
        let target = noid_chain::consensus::next_target(
            checkpoint.asert_anchor.anchor_height,
            checkpoint.asert_anchor.anchor_timestamp,
            &checkpoint.asert_anchor.anchor_target,
            checkpoint.parent_header.height + 1,
            checkpoint.parent_header.timestamp,
            timestamp,
        );
        let mut output_slot_cursor = checkpoint.output_slot_cursor;
        let mut reserved = std::collections::BTreeSet::new();
        let mut candidates = Vec::with_capacity(user_count);
        let mut wallet_authorities = Vec::with_capacity(user_count - contract_count);
        let mut contract_records = Vec::with_capacity(contract_count);

        #[derive(Clone)]
        struct ContractRecord {
            logical_txid: TxBodyHash,
            authority_seed: u128,
            wrong_authority_seed: u128,
            corrupt_authorization: bool,
            component: noid_recursive::V2ContractComponentInput,
        }

        for (tx_index, source) in checkpoint.spendables.iter().take(user_count).enumerate() {
            let slot = checkpoint.parent_state.state.slot(source.slot_index);
            if slot.is_empty() {
                return Err("research child source slot is empty".into());
            }
            let mut output_slots = [0u32; TX_OUTPUTS];
            for output_slot in &mut output_slots {
                while checkpoint.parent_state.state.slot(output_slot_cursor)
                    != noid_chain::SlotValue::EMPTY
                    || reserved.contains(&output_slot_cursor)
                {
                    output_slot_cursor = output_slot_cursor
                        .checked_add(1)
                        .ok_or_else(|| "research output slot overflow".to_owned())?;
                }
                *output_slot = output_slot_cursor;
                reserved.insert(output_slot_cursor);
                output_slot_cursor = output_slot_cursor
                    .checked_add(1)
                    .ok_or_else(|| "research output slot overflow".to_owned())?;
            }
            let mut inputs = [TxInput::dummy(); TX_INPUTS];
            inputs[0] = TxInput {
                slot_index: source.slot_index,
                amount: slot.amount(),
                creation_id: slot.creation_id(),
            };

            if tx_index < contract_count {
                let object = &objects[tx_index];
                if [slot.owner_hi, slot.owner_lo] != object.old_root.as_fields() {
                    return Err("research object root was not installed in parent State".into());
                }
                let terminal = tx_index % 2 == 1;
                let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
                outputs[0] = TxOutput {
                    slot_index: output_slots[0],
                    amount: 0,
                    owner: Address([0u8; 32]),
                };
                let mut body = TxBody {
                    epoch_anchor: checkpoint.start_accumulator.epoch_anchor_id,
                    fee: 0,
                    input_owner: object.old_root,
                    inputs,
                    outputs,
                    validity_bitmap: 1
                        | output_bitmap_bit(0)
                        | PAGED_SPEND_START_BIT
                        | PAGED_SPEND_END_BIT
                        | PAGED_SPEND_CONTRACT_BIT
                        | if terminal {
                            PAGED_SPEND_TERMINAL_BIT
                        } else {
                            0
                        },
                    is_coinbase: false,
                };
                let ordinary_floor = noid_chain::consensus::fees::fee_breakdown(
                    1,
                    2,
                    checkpoint.parent_state.active_slot_count,
                    checkpoint.parent_header.log_slots,
                )
                .required_total;
                body.fee = ordinary_floor
                    .checked_add((contract_count - tx_index) as u64)
                    .ok_or_else(|| "research contract fee overflow".to_owned())?;
                body.outputs[0].amount = slot
                    .amount()
                    .checked_sub(body.fee)
                    .ok_or_else(|| "research object does not cover its fee".to_owned())?;
                let contexts = v2_contract_context(&body);
                let next = v2_execute_program(
                    object.current,
                    &object.program,
                    &body,
                    checkpoint.parent_header.height + 1,
                    object.deadline,
                );
                let before_deadline = checkpoint.parent_header.height + 1 < object.deadline;
                body.outputs[0].owner = if terminal {
                    v2_address(if before_deadline {
                        object.claim_recipient
                    } else {
                        object.refund_recipient
                    })
                } else {
                    v2_object_root(
                        &object.program,
                        next,
                        object.controller,
                        object.refund_authority,
                        object.deadline,
                        object.claim_recipient,
                        object.refund_recipient,
                    )
                };
                if mutation == V2ResearchMutation::WrongTerminalRecipient && tx_index == 1 {
                    body.outputs[0].owner =
                        derive_address(&mk_secret(self.seed.wrapping_add(0xBAD0_0000_0000_0001)));
                }
                let page = TxPage::new(body.clone())
                    .map_err(|error| format!("research contract page: {error}"))?;
                let logical_txid = hash_paged_spend(std::slice::from_ref(&page))
                    .map_err(|error| format!("research contract group: {error}"))?;
                let mut component = noid_recursive::V2ContractComponentInput {
                    body_index: 0,
                    live: true,
                    program: object.program,
                    current: object.current,
                    contexts,
                    next,
                    controller: object.controller,
                    refund_authority: object.refund_authority,
                    terminal,
                    deadline: object.deadline,
                    claim_recipient: object.claim_recipient,
                    refund_recipient: object.refund_recipient,
                    rules: v2_research_rules(),
                };
                if tx_index == 0 {
                    match mutation {
                        V2ResearchMutation::InvalidOpcodeOpening => {
                            component.program[0][0] = Block128::from(15u128);
                        }
                        V2ResearchMutation::WrongNextOpening => {
                            component.next += Block128::from(1u128);
                        }
                        V2ResearchMutation::WrongContextOpening => {
                            component.contexts[0] += Block128::from(1u128);
                        }
                        _ => {}
                    }
                }
                contract_records.push(ContractRecord {
                    logical_txid,
                    authority_seed: if before_deadline {
                        object.controller_seed
                    } else {
                        object.refund_authority_seed
                    },
                    wrong_authority_seed: if before_deadline {
                        object.refund_authority_seed
                    } else {
                        object.controller_seed
                    },
                    corrupt_authorization: mutation == V2ResearchMutation::WrongBranchAuthorization
                        && tx_index == 1,
                    component,
                });
                candidates.push(Transaction::new(body));
            } else {
                let spend_secret = source.spend_secret();
                let owner = derive_address(&spend_secret);
                if [slot.owner_hi, slot.owner_lo] != owner.as_fields() {
                    return Err("research wallet source owner mismatch".into());
                }
                let output_seeds: [u128; TX_OUTPUTS] = std::array::from_fn(|output_index| {
                    self.seed
                        .wrapping_add(0x2200_0000)
                        .wrapping_add((contract_count as u128) << 32)
                        .wrapping_add((tx_index as u128) << 4)
                        .wrapping_add(output_index as u128)
                });
                let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
                for index in 0..TX_OUTPUTS {
                    outputs[index] = TxOutput {
                        slot_index: output_slots[index],
                        amount: 1,
                        owner: derive_address(&mk_secret(output_seeds[index])),
                    };
                }
                let mut body = TxBody {
                    epoch_anchor: checkpoint.start_accumulator.epoch_anchor_id,
                    fee: 0,
                    input_owner: owner,
                    inputs,
                    outputs,
                    validity_bitmap: 1
                        | output_bitmap_bit(0)
                        | output_bitmap_bit(1)
                        | PAGED_SPEND_START_BIT
                        | PAGED_SPEND_END_BIT,
                    is_coinbase: false,
                };
                body.fee = noid_chain::consensus::fees::required_fee_for_tx_body(
                    &body,
                    checkpoint.parent_state.active_slot_count,
                    checkpoint.parent_header.log_slots,
                );
                let spendable = slot
                    .amount()
                    .checked_sub(body.fee)
                    .ok_or_else(|| "research wallet input does not cover its fee".to_owned())?;
                body.outputs[0].amount = spendable / 2;
                body.outputs[1].amount = spendable - body.outputs[0].amount;
                let page = TxPage::new(body.clone())
                    .map_err(|error| format!("research wallet page: {error}"))?;
                let logical_txid = hash_paged_spend(std::slice::from_ref(&page))
                    .map_err(|error| format!("research wallet group: {error}"))?;
                wallet_authorities.push((logical_txid, source.spend_secret_seed));
                candidates.push(Transaction::new(body));
            }
        }

        let miner_seed = self
            .seed
            .wrapping_add(0x3900_0000)
            .wrapping_add(contract_count as u128);
        let template = noid_chain::consensus::build_block_template(
            &checkpoint.parent_header,
            &checkpoint.parent_state,
            &checkpoint.finalized_active_counts,
            candidates,
            derive_address(&mk_secret(miner_seed)),
            timestamp,
            target,
        )
        .map_err(|error| format!("build research B{TIER} template: {error:?}"))?;
        if template.txs.len() != user_count {
            return Err(format!(
                "research B{TIER} retained {} of {user_count} users",
                template.txs.len()
            ));
        }
        for (index, tx) in template.txs.iter().enumerate() {
            let marked = tx.body.validity_bitmap & PAGED_SPEND_CONTRACT_BIT != 0;
            if marked != (index < contract_count) {
                return Err("fee ordering did not retain the contract prefix".into());
            }
        }

        let mut ordered_contracts = Vec::with_capacity(contract_count);
        let authorization_proofs = template
            .txs
            .iter()
            .map(|transaction| -> Result<ZkAuthorizationProof, String> {
                let page = TxPage {
                    body: transaction.body.clone(),
                };
                let logical_txid = hash_paged_spend(std::slice::from_ref(&page))
                    .map_err(|error| format!("hash research PagedSpend: {error}"))?;
                if let Some(record) = contract_records
                    .iter()
                    .find(|record| record.logical_txid == logical_txid)
                {
                    ordered_contracts.push(record.component.clone());
                    let before_deadline =
                        checkpoint.parent_header.height + 1 < record.component.deadline;
                    let selected_authority = if before_deadline {
                        record.component.controller
                    } else {
                        record.component.refund_authority
                    };
                    let wrong_authority = if before_deadline {
                        record.component.refund_authority
                    } else {
                        record.component.controller
                    };
                    return prove_v2_contract_controller_authorization(
                        std::slice::from_ref(&page),
                        if record.corrupt_authorization {
                            wrong_authority
                        } else {
                            selected_authority
                        },
                        OwnerAuthWitness::new(mk_secret(if record.corrupt_authorization {
                            record.wrong_authority_seed
                        } else {
                            record.authority_seed
                        })),
                    )
                    .map(|bundle| bundle.proof)
                    .map_err(|error| format!("prove research contract controller: {error}"));
                }
                let seed = wallet_authorities
                    .iter()
                    .find_map(|(txid, seed)| (txid == &logical_txid).then_some(*seed))
                    .ok_or_else(|| "research template lost its wallet authority".to_owned())?;
                prove_paged_spend_authorization(
                    std::slice::from_ref(&page),
                    OwnerAuthWitness::new(mk_secret(seed)),
                )
                .map(|bundle| bundle.proof)
                .map_err(|error| format!("prove research wallet authorization: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if ordered_contracts.len() != contract_count {
            return Err("research template lost a contract record".into());
        }

        let block = template.into_block(0);
        let stream = noid_chain::validate_block_page_stream(&block.transactions)
            .map_err(|error| format!("research block stream: {error}"))?;
        for (index, component) in ordered_contracts.iter_mut().enumerate() {
            component.body_index = stream.user_start_index + index;
        }
        let end_accumulator = checkpoint
            .start_accumulator
            .advance(&checkpoint.parent_header, &block.header)
            .map_err(|error| format!("advance research B{TIER} accumulator: {error:?}"))?;
        let context = noid_block::HistoryStepPreparationContext {
            parent_header: &checkpoint.parent_header,
            tx_epoch_anchor_header: &checkpoint.tx_epoch_anchor_header,
            parent_state: &checkpoint.parent_state,
            start_accumulator: &checkpoint.start_accumulator,
            previous_timestamps: &checkpoint.previous_timestamps,
            finalized_active_counts: &checkpoint.finalized_active_counts,
            asert_anchor: &checkpoint.asert_anchor,
            local_time: timestamp,
        };
        let prepared = noid_block::prepare_v2_research_history_step_input_witness::<TIER>(
            block,
            context,
            authorization_proofs,
            &self.ghost,
            ordered_contracts,
        )
        .map_err(|error| format!("prepare research B{TIER} HistoryStep: {error}"))?;
        prepared
            .finish_template(&checkpoint.start_accumulator, &end_accumulator)
            .map(|(_, input)| input)
            .map_err(|error| format!("finish research B{TIER} HistoryStep: {error}"))
    }

    fn fork<const TIER: usize>(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
        user_count: usize,
    ) -> Result<PreparedHistoryStepTierFixture<TIER>, String> {
        if class_id.current_tier() != TIER {
            return Err(format!(
                "class {} selects B{}, not requested B{TIER}",
                class_id.index(),
                class_id.current_tier(),
            ));
        }
        // The requested start boundary identifies the parent checkpoint;
        // the class no longer encodes a parent tier.
        let checkpoint = self
            .checkpoints
            .iter()
            .flatten()
            .find(|checkpoint| &checkpoint.start_accumulator == expected_start)
            .ok_or_else(|| {
                format!(
                    "class {} start does not match any built parent checkpoint",
                    class_id.index(),
                )
            })?;
        self.build_child_from::<TIER>(checkpoint, user_count, 0x1000 + class_id.index() as u128)
            .map(|child| child.prepared)
    }

    fn build_child<const TIER: usize>(
        &self,
        user_count: usize,
        nonce_domain: u128,
    ) -> Result<BuiltFixtureChild<TIER>, String> {
        self.build_child_from::<TIER>(&self.live, user_count, nonce_domain)
    }

    fn build_child_from<const TIER: usize>(
        &self,
        checkpoint: &HistoryStepFixtureCheckpoint,
        user_count: usize,
        nonce_domain: u128,
    ) -> Result<BuiltFixtureChild<TIER>, String> {
        if noid_chain::consensus::params::block_page_class_tier(user_count) != Some(TIER) {
            return Err(format!("{user_count} users do not select B{TIER}"));
        }
        let (candidates, authorities, next_user_spendables, next_output_slot_cursor) =
            child_user_transactions(checkpoint, user_count, self.seed, nonce_domain)?;
        let timestamp = checkpoint
            .parent_header
            .timestamp
            .checked_add(noid_chain::consensus::params::BLOCK_TIME)
            .ok_or_else(|| "fixture timestamp overflow".to_owned())?;
        let target = noid_chain::consensus::next_target(
            checkpoint.asert_anchor.anchor_height,
            checkpoint.asert_anchor.anchor_timestamp,
            &checkpoint.asert_anchor.anchor_target,
            checkpoint.parent_header.height + 1,
            checkpoint.parent_header.timestamp,
            timestamp,
        );
        let miner_seed = self
            .seed
            .wrapping_add(0x3000_0000)
            .wrapping_add(nonce_domain << 12)
            .wrapping_add(checkpoint.parent_header.height as u128);
        let template = noid_chain::consensus::build_block_template(
            &checkpoint.parent_header,
            &checkpoint.parent_state,
            &checkpoint.finalized_active_counts,
            candidates,
            derive_address(&mk_secret(miner_seed)),
            timestamp,
            target,
        )
        .map_err(|error| format!("build honest B{TIER} template: {error:?}"))?;
        if template.txs.len() != user_count {
            return Err(format!(
                "honest B{TIER} template retained {} of {user_count} users",
                template.txs.len(),
            ));
        }
        let authorization_proofs = template
            .txs
            .iter()
            .map(|transaction| -> Result<ZkAuthorizationProof, String> {
                let page = TxPage {
                    body: transaction.body.clone(),
                };
                let logical_txid = hash_paged_spend(std::slice::from_ref(&page))
                    .map_err(|error| format!("hash honest PagedSpend: {error}"))?;
                let seed = authorities
                    .iter()
                    .find_map(|(txid, seed)| (txid == &logical_txid).then_some(*seed))
                    .ok_or_else(|| "ordered template lost its wallet authority".to_owned())?;
                let cached_proof = {
                    self.authorization_proofs
                        .borrow()
                        .get(&logical_txid)
                        .cloned()
                };
                if let Some(proof) = cached_proof {
                    return Ok(proof);
                }
                let proof = prove_paged_spend_authorization(
                    std::slice::from_ref(&page),
                    OwnerAuthWitness::new(mk_secret(seed)),
                )
                .map(|bundle| bundle.proof)
                .map_err(|error| format!("prove honest wallet authorization: {error}"))?;
                self.authorization_proofs
                    .borrow_mut()
                    .insert(logical_txid, proof.clone());
                Ok(proof)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authorization_bytes = authorization_proofs
            .into_iter()
            .map(|proof| {
                WalletAuthorizationBundle { proof }
                    .to_bytes()
                    .map_err(|error| format!("encode honest wallet authorization: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let block = template.into_block(0);
        let nonce_key = noid_chain::hash_block_header(&block.header);
        let cached_nonce = { self.mined_nonces.borrow().get(&nonce_key).copied() };
        let nonce = if let Some(nonce) = cached_nonce {
            nonce
        } else {
            let nonce = mine_history_step_fixture_header(&block.header);
            self.mined_nonces.borrow_mut().insert(nonce_key, nonce);
            nonce
        };
        let mut sealed_block = block.clone();
        sealed_block.header.nonce = nonce;
        let end_accumulator = checkpoint
            .start_accumulator
            .advance(&checkpoint.parent_header, &sealed_block.header)
            .map_err(|error| format!("advance honest B{TIER} accumulator: {error:?}"))?;
        let context = noid_block::HistoryStepPreparationContext {
            parent_header: &checkpoint.parent_header,
            tx_epoch_anchor_header: &checkpoint.tx_epoch_anchor_header,
            parent_state: &checkpoint.parent_state,
            start_accumulator: &checkpoint.start_accumulator,
            previous_timestamps: &checkpoint.previous_timestamps,
            finalized_active_counts: &checkpoint.finalized_active_counts,
            asert_anchor: &checkpoint.asert_anchor,
            local_time: timestamp,
        };
        let input_preparation_started = Instant::now();
        let authorization_weight = authorization_bytes
            .iter()
            .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
            .ok_or_else(|| "honest authorization byte weight overflow".to_owned())?;
        let payload_weight = block
            .to_bytes()
            .len()
            .checked_add(authorization_weight)
            .ok_or_else(|| "honest block byte weight overflow".to_owned())?;
        std::hint::black_box(payload_weight);
        let stream = noid_chain::validate_block_page_stream(&block.transactions)
            .map_err(|error| format!("honest block body is non-canonical: {error}"))?;
        if usize::from(stream.page_count) != user_count {
            return Err(format!(
                "honest block has {} user pages, expected {user_count}",
                stream.page_count
            ));
        }
        let authorization_proofs = authorization_bytes
            .into_iter()
            .enumerate()
            .map(|(index, encoded)| {
                WalletAuthorizationBundle::from_bytes(&encoded)
                    .map(|bundle| bundle.proof)
                    .map_err(|error| format!("decode honest wallet authorization {index}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let witness = noid_block::prepare_history_step_input_witness::<TIER>(
            block,
            context,
            authorization_proofs,
            &self.ghost,
        )
        .map_err(|error| format!("prepare honest B{TIER} HistoryStep: {error}"))?;
        let input_preparation = input_preparation_started.elapsed();

        let mut next_spendables = Vec::with_capacity(
            checkpoint.spendables.len() - user_count + 1 + next_user_spendables.len(),
        );
        next_spendables.extend(checkpoint.spendables.iter().skip(user_count).cloned());
        let coinbase_slot = sealed_block.transactions[0]
            .body
            .live_outputs()
            .next()
            .ok_or_else(|| "honest coinbase has no live output".to_owned())?
            .1
            .slot_index;
        next_spendables.push(TrackedSpendable {
            slot_index: coinbase_slot,
            spend_secret_seed: miner_seed,
        });
        next_spendables.extend(next_user_spendables);

        Ok(BuiltFixtureChild {
            prepared: PreparedHistoryStepTierFixture {
                witness,
                nonce,
                start_accumulator: checkpoint.start_accumulator.clone(),
                end_accumulator,
                input_preparation,
                user_pages: user_count,
            },
            sealed_block,
            next_spendables,
            next_output_slot_cursor,
        })
    }
}

impl noid_recursive::HistoryStepFreezeInputProvider for HonestHistoryStepFixtureProvider {
    type Error = String;

    fn reset_backbone(&mut self) -> Result<(), Self::Error> {
        HonestHistoryStepFixtureProvider::reset_backbone(self);
        Ok(())
    }

    fn next_backbone(
        &mut self,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<Option<noid_recursive::HistoryStepFreezeInput>, Self::Error> {
        HonestHistoryStepFixtureProvider::next_backbone(self, expected_start)?
            .map(|step| match step.input {
                PreparedHistoryStepBackboneInput::B25(input) => input
                    .into_history_step_input()
                    .map(noid_recursive::HistoryStepFreezeInput::B25),
                PreparedHistoryStepBackboneInput::B255(input) => input
                    .into_history_step_input()
                    .map(noid_recursive::HistoryStepFreezeInput::B255),
            })
            .transpose()
    }

    fn b25(
        &mut self,
        class: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<noid_recursive::HistoryStepBlockInput<25>, Self::Error> {
        HonestHistoryStepFixtureProvider::b25(self, class, expected_start)?
            .into_history_step_input()
    }

    fn b255(
        &mut self,
        class: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<noid_recursive::HistoryStepBlockInput<255>, Self::Error> {
        HonestHistoryStepFixtureProvider::b255(self, class, expected_start)?
            .into_history_step_input()
    }
}

trait AdvanceHonestBackbone {
    fn map_into(
        self,
        live: &mut HistoryStepFixtureCheckpoint,
    ) -> Result<PreparedHistoryStepBackboneInput, String>;
}

macro_rules! impl_advance_honest_backbone {
    ($tier:literal, $variant:ident) => {
        impl AdvanceHonestBackbone for BuiltFixtureChild<$tier> {
            fn map_into(
                self,
                live: &mut HistoryStepFixtureCheckpoint,
            ) -> Result<PreparedHistoryStepBackboneInput, String> {
                let Self {
                    prepared,
                    sealed_block,
                    next_spendables,
                    next_output_slot_cursor,
                } = self;
                noid_chain::consensus::validate_block_checks(
                    &sealed_block,
                    &live.parent_header,
                    &live.previous_timestamps,
                    &live.finalized_active_counts,
                    sealed_block.header.timestamp,
                    &live.asert_anchor,
                )
                .map_err(|error| format!("validate honest B{} backbone: {error}", $tier))?;
                noid_chain::materialize_accepted_block_state(&mut live.parent_state, &sealed_block)
                    .map_err(|error| {
                        format!("materialize honest B{} backbone: {error:?}", $tier)
                    })?;
                if live.parent_state.cached_state_root() != sealed_block.header.state_root {
                    return Err(format!("honest B{} state root did not materialize", $tier));
                }
                live.previous_timestamps.push(sealed_block.header.timestamp);
                live.start_accumulator = prepared.end_accumulator.clone();
                live.parent_header = sealed_block.header;
                live.spendables = next_spendables;
                live.output_slot_cursor = next_output_slot_cursor;
                Ok(PreparedHistoryStepBackboneInput::$variant(prepared))
            }
        }
    };
}

impl_advance_honest_backbone!(25, B25);
impl_advance_honest_backbone!(255, B255);

fn genesis_fixture_checkpoint() -> HistoryStepFixtureCheckpoint {
    let genesis = noid_chain::consensus::genesis_header();
    let state = noid_chain::state::ChainState::with_log_slots(genesis.log_slots as usize);
    assert_eq!(state.cached_state_root(), genesis.state_root);
    HistoryStepFixtureCheckpoint {
        parent_header: genesis,
        tx_epoch_anchor_header: genesis,
        parent_state: state,
        start_accumulator: noid_recursive::genesis_accumulator(),
        previous_timestamps: vec![genesis.timestamp],
        // This short release fixture never reaches the first complete
        // hard-finalized expansion window.
        finalized_active_counts: Vec::new(),
        asert_anchor: noid_chain::consensus::AnchorInfo {
            anchor_height: genesis.height,
            anchor_timestamp: genesis.timestamp,
            anchor_target: genesis.difficulty_target,
        },
        spendables: Vec::new(),
        output_slot_cursor: 1 << (BENCH_LOG_SLOTS - 1),
    }
}

fn child_user_transactions(
    checkpoint: &HistoryStepFixtureCheckpoint,
    user_count: usize,
    seed: u128,
    nonce_domain: u128,
) -> Result<
    (
        Vec<Transaction>,
        Vec<(TxBodyHash, u128)>,
        Vec<TrackedSpendable>,
        u32,
    ),
    String,
> {
    if checkpoint.spendables.len() < user_count {
        return Err(format!(
            "honest parent has {} spendables, needs {user_count}",
            checkpoint.spendables.len(),
        ));
    }
    let mut output_slot_cursor = checkpoint.output_slot_cursor;
    let mut reserved = std::collections::BTreeSet::new();
    let mut transactions = Vec::with_capacity(user_count);
    let mut authorities = Vec::with_capacity(user_count);
    let mut next_spendables = Vec::with_capacity(user_count * TX_OUTPUTS);

    for (tx_index, source) in checkpoint.spendables.iter().take(user_count).enumerate() {
        let slot = checkpoint.parent_state.state.slot(source.slot_index);
        if slot.is_empty() {
            return Err("tracked honest input is not live".into());
        }
        let spend_secret = source.spend_secret();
        let owner = derive_address(&spend_secret);
        if [slot.owner_hi, slot.owner_lo] != owner.as_fields() {
            return Err("tracked honest input owner does not match its wallet secret".into());
        }
        let mut output_slots = [0u32; TX_OUTPUTS];
        for output_slot in &mut output_slots {
            while checkpoint.parent_state.state.slot(output_slot_cursor)
                != noid_chain::SlotValue::EMPTY
                || reserved.contains(&output_slot_cursor)
            {
                output_slot_cursor = output_slot_cursor
                    .checked_add(1)
                    .ok_or_else(|| "honest fixture output slot overflow".to_owned())?;
            }
            *output_slot = output_slot_cursor;
            reserved.insert(output_slot_cursor);
            output_slot_cursor = output_slot_cursor
                .checked_add(1)
                .ok_or_else(|| "honest fixture output slot overflow".to_owned())?;
        }
        let output_seeds: [u128; TX_OUTPUTS] = std::array::from_fn(|output_index| {
            seed.wrapping_add(0x2000_0000)
                .wrapping_add(nonce_domain << 20)
                .wrapping_add((tx_index as u128) << 4)
                .wrapping_add(output_index as u128)
        });
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: source.slot_index,
            amount: slot.amount(),
            creation_id: slot.creation_id(),
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        for index in 0..TX_OUTPUTS {
            outputs[index] = TxOutput {
                slot_index: output_slots[index],
                amount: 1,
                owner: derive_address(&mk_secret(output_seeds[index])),
            };
        }
        let mut body = TxBody {
            epoch_anchor: checkpoint.start_accumulator.epoch_anchor_id,
            fee: 0,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1
                | output_bitmap_bit(0)
                | output_bitmap_bit(1)
                | PAGED_SPEND_START_BIT
                | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        };
        body.fee = noid_chain::consensus::fees::required_fee_for_tx_body(
            &body,
            checkpoint.parent_state.active_slot_count,
            checkpoint.parent_header.log_slots,
        );
        let spendable = slot
            .amount()
            .checked_sub(body.fee)
            .ok_or_else(|| "honest input does not cover the consensus fee".to_owned())?;
        body.outputs[0].amount = spendable / 2;
        body.outputs[1].amount = spendable - body.outputs[0].amount;
        let page = TxPage::new(body.clone())
            .map_err(|error| format!("honest PagedSpend page: {error}"))?;
        let txid = hash_paged_spend(std::slice::from_ref(&page))
            .map_err(|error| format!("honest PagedSpend group: {error}"))?;
        authorities.push((txid, source.spend_secret_seed));
        transactions.push(Transaction::new(body));
        next_spendables.extend((0..TX_OUTPUTS).map(|index| TrackedSpendable {
            slot_index: output_slots[index],
            spend_secret_seed: output_seeds[index],
        }));
    }
    Ok((
        transactions,
        authorities,
        next_spendables,
        output_slot_cursor,
    ))
}

fn mine_history_step_fixture_header(header: &noid_chain::BlockHeader) -> u128 {
    use rayon::prelude::*;

    const NONCES_PER_LANE: u128 = 65_536;
    let lanes = rayon::current_num_threads().max(1);
    let batch_width = NONCES_PER_LANE * lanes as u128;
    let mut batch_start = 0u128;
    loop {
        if let Some(nonce) = (0..lanes)
            .into_par_iter()
            .filter_map(|lane| {
                noid_chain::consensus::pow::search_pow(
                    header,
                    batch_start + NONCES_PER_LANE * lane as u128,
                    NONCES_PER_LANE,
                )
            })
            .min()
        {
            return nonce;
        }
        batch_start = batch_start
            .checked_add(batch_width)
            .expect("fixture PoW nonce space exhausted");
    }
}

#[cfg(test)]
mod two_class_history_step_fixture_tests {
    use super::*;

    #[test]
    fn freezer_page_counts_select_only_b25_and_b255() {
        let backbone = HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS
            .map(|count| noid_chain::consensus::params::block_page_class_tier(count).unwrap());
        assert_eq!(backbone, [25, 25, 25, 25, 25, 25, 255]);
        let forks = HISTORY_STEP_FREEZER_FORK_USER_COUNTS
            .map(|count| noid_chain::consensus::params::block_page_class_tier(count).unwrap());
        assert_eq!(forks, [25, 255]);
    }

    #[test]
    #[ignore = "runs real wallet proving and production PoW"]
    fn first_backbone_step_is_a_coinbase_only_b25_block() {
        let mut provider = HonestHistoryStepFixtureProvider::new(0x4849_5354_4550).unwrap();
        let genesis = noid_recursive::genesis_accumulator();
        let step = provider.next_backbone(&genesis).unwrap().unwrap();
        assert!(step.capture_parent_slot.is_none());
        let PreparedHistoryStepBackboneInput::B25(prepared) = step.input else {
            panic!("height one must select B25");
        };
        let (witness, nonce, start, end) = prepared.into_parts();
        let (block, _) = witness.finish(nonce, &start, &end).unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.transactions.len(), 1);
    }
}

fn v2_research_rules() -> noid_tx::experimental_object::ObjectRules {
    noid_tx::experimental_object::ObjectRules {
        max_fee: u64::MAX,
        min_retained: 0,
        max_payout: u64::MAX,
        modes: 31,
    }
}
