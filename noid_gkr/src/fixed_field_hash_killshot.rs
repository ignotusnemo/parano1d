// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-field Poseidon2b KillShot.
//!
//! This component proves a fixed no-padding field sponge schedule:
//!
//! ```text
//! digest = Poseidon2b(domain_tag, fields[0..n_fields])
//! ```
//!
//! `n_fields` must be even. The caller is responsible for putting any
//! per-language marker and field-count words into `fields` before proving.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, DomainTag};
use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, MDS_FULL, N_ROUNDS, STATE_SIZE};

use crate::batch_eval::{
    prove_linear_eval_prebound, prove_multi_batch_eval, verify_linear_eval_prebound,
    verify_multi_batch_eval, BatchEvalReduction, EvalClaim, LinearEvalClaim, LinearEvalProof,
    LinearEvalTerm, MultiBatchEvalProof,
};
use crate::block_spine::{
    block_spine_state_point, prove_block_spine_shift, prove_block_spine_unified,
    verify_block_spine_shift, verify_block_spine_unified, BlockSpineKillShotProof, BlockSpineMle,
    BlockSpineUnifiedReduction,
};

pub const FIXED_FIELD_HASH_PIN_LANES: usize = 2;
const DEFAULT_LINEAR_RELATION_TAG: u128 = 0x4649_5848_4153_4801; // "FIXHASH"+1

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedFieldHashParams {
    pub domain_tag: DomainTag,
    pub n_fields: usize,
    pub relation_tag: u128,
}

impl FixedFieldHashParams {
    pub fn new(domain_tag: DomainTag, n_fields: usize, relation_tag: u128) -> Option<Self> {
        if n_fields == 0 || !n_fields.is_multiple_of(2) {
            return None;
        }
        Some(Self {
            domain_tag,
            n_fields,
            relation_tag,
        })
    }

    pub fn with_default_relation_tag(domain_tag: DomainTag, n_fields: usize) -> Option<Self> {
        let relation_tag =
            ((domain_tag.as_u64() as u128) << 64) ^ DEFAULT_LINEAR_RELATION_TAG ^ n_fields as u128;
        Self::new(domain_tag, n_fields, relation_tag)
    }

    #[inline]
    fn n_blocks(self) -> usize {
        self.n_fields / 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedFieldHashInputs {
    pub fields: Vec<Block128>,
    pub expected_digest: [Block128; FIXED_FIELD_HASH_PIN_LANES],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FixedFieldHashProofKillShot {
    pub kill_shot: BlockSpineKillShotProof,
    pub chain: LinearEvalProof,
    pub batch: MultiBatchEvalProof,
    pub n_claims: usize,
    pub n_fields: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl FixedFieldHashProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys = self
            .kill_shot
            .main
            .round_polys
            .iter()
            .map(|round| round.coeffs_no_linear.len() * 16)
            .sum::<usize>();
        let shift_polys = self
            .kill_shot
            .shift
            .round_polys
            .iter()
            .map(|round| round.coeffs_no_linear.len() * 16)
            .sum::<usize>();
        let main_finals = 12 * 16;
        let shift_finals = 3 * 16;
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.chain.byte_len()
            + self.batch.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedFieldHashReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

fn input_blocks(input: &FixedFieldHashInputs) -> impl Iterator<Item = [Block128; 2]> + '_ {
    input.fields.chunks_exact(2).map(|pair| [pair[0], pair[1]])
}

fn validate_inputs(params: FixedFieldHashParams, inputs: &[FixedFieldHashInputs]) -> bool {
    !inputs.is_empty()
        && params.n_fields != 0
        && params.n_fields.is_multiple_of(2)
        && inputs
            .iter()
            .all(|input| input.fields.len() == params.n_fields)
}

fn absorb_public_batch<T: FiatShamir<Block128>>(
    params: FixedFieldHashParams,
    channel: &mut T,
    inputs: &[FixedFieldHashInputs],
) {
    channel.absorb(Block128::from(inputs.len() as u128));
    channel.absorb(Block128::from(params.domain_tag.as_u64() as u128));
    channel.absorb(Block128::from(params.n_fields as u128));
    channel.absorb(Block128::from(params.relation_tag));
    for input in inputs {
        for &field in &input.fields {
            channel.absorb(field);
        }
        for lane in input.expected_digest {
            channel.absorb(lane);
        }
    }
}

fn evaluate_claims(
    params: FixedFieldHashParams,
    inputs: &[FixedFieldHashInputs],
) -> Option<Vec<[Block128; STATE_SIZE]>> {
    if !validate_inputs(params, inputs) {
        return None;
    }
    let perm = Poseidon2bPermutation;
    let iv = capacity_iv(params.domain_tag);
    let mut slot_state_ins = Vec::with_capacity(inputs.len() * params.n_blocks());
    for input in inputs {
        let mut state = [Block128::ZERO, Block128::ZERO, iv[0], iv[1]];
        for block in input_blocks(input) {
            state[0] += block[0];
            state[1] += block[1];
            slot_state_ins.push(state);
            perm.permute_mut(&mut state);
        }
        if state[..FIXED_FIELD_HASH_PIN_LANES] != input.expected_digest {
            return None;
        }
    }
    Some(slot_state_ins)
}

fn state_claim(num_vars: usize, slot: usize, round: usize, lane: usize) -> LinearEvalTerm {
    LinearEvalTerm {
        point: block_spine_state_point(num_vars, slot, round, lane),
        coeff: Block128::ONE,
    }
}

fn weighted_state_claim(
    num_vars: usize,
    slot: usize,
    round: usize,
    lane: usize,
    coeff: Block128,
) -> LinearEvalTerm {
    LinearEvalTerm {
        point: block_spine_state_point(num_vars, slot, round, lane),
        coeff,
    }
}

#[inline]
fn mds_coeff(row: usize, col: usize) -> Block128 {
    Block128::from(MDS_FULL[row][col])
}

fn mds_constant(row: usize, inputs: &[(usize, Block128)]) -> Block128 {
    inputs
        .iter()
        .map(|&(col, value)| mds_coeff(row, col) * value)
        .fold(Block128::ZERO, |a, b| a + b)
}

fn push_prev_terms(terms: &mut Vec<LinearEvalTerm>, num_vars: usize, prev_slot: usize, row: usize) {
    for src_lane in 0..STATE_SIZE {
        terms.push(weighted_state_claim(
            num_vars,
            prev_slot,
            N_ROUNDS,
            src_lane,
            mds_coeff(row, src_lane),
        ));
    }
}

fn claim_chain_claims(
    params: FixedFieldHashParams,
    inputs: &[FixedFieldHashInputs],
    num_vars: usize,
) -> Vec<LinearEvalClaim> {
    let iv = capacity_iv(params.domain_tag);
    let mut claims = Vec::new();
    let n_blocks = params.n_blocks();
    for (idx, input) in inputs.iter().enumerate() {
        let base = idx * n_blocks;
        for (block_idx, block) in input_blocks(input).enumerate() {
            let slot = base + block_idx;
            for lane in 0..STATE_SIZE {
                let mut terms = vec![state_claim(num_vars, slot, 0, lane)];
                let value = if block_idx == 0 {
                    mds_constant(
                        lane,
                        &[(0, block[0]), (1, block[1]), (2, iv[0]), (3, iv[1])],
                    )
                } else {
                    push_prev_terms(&mut terms, num_vars, slot - 1, lane);
                    mds_constant(lane, &[(0, block[0]), (1, block[1])])
                };
                claims.push(LinearEvalClaim { terms, value });
            }
        }
        let last_slot = base + n_blocks - 1;
        for lane in 0..FIXED_FIELD_HASH_PIN_LANES {
            claims.push(LinearEvalClaim {
                terms: vec![state_claim(num_vars, last_slot, N_ROUNDS, lane)],
                value: input.expected_digest[lane],
            });
        }
    }
    claims
}

pub fn prove_fixed_field_hash_killshot<T: FiatShamir<Block128>>(
    params: FixedFieldHashParams,
    inputs: &[FixedFieldHashInputs],
    channel: &mut T,
) -> (FixedFieldHashProofKillShot, FixedFieldHashReductions) {
    let slot_state_ins =
        evaluate_claims(params, inputs).expect("prover asked to prove wrong fixed-field hash");

    absorb_public_batch(params, channel, inputs);

    let mle = BlockSpineMle::build_from_slot_state_ins(&slot_state_ins);
    let (main, r_prime) = prove_block_spine_unified(&mle, channel);
    let main_red = BlockSpineUnifiedReduction {
        r_prime: r_prime.clone(),
        s_in_dec_at_r: main.s_in_dec_at_r,
        s_out_dec_at_r: main.s_out_dec_at_r,
        state_dec_at_r: main.state_dec_at_r,
        state_at_r: main.state_at_r,
        s_out_lane_dec_at_r: main.s_out_lane_dec_at_r,
        state_lane_dec_at_r: main.state_lane_dec_at_r,
        beta: Block128::ZERO,
        gamma: Block128::ZERO,
    };
    let (shift, r_double_prime) = prove_block_spine_shift(&mle, &r_prime, &main_red, channel);

    let chain_claims = claim_chain_claims(params, inputs, mle.num_vars);
    let (chain, chain_red) =
        prove_linear_eval_prebound(&mle.state, &chain_claims, params.relation_tag, channel);

    let state_claims = vec![
        EvalClaim {
            point: r_prime,
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
        },
    ];
    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];
    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let columns: [&[Block128]; 3] = [&mle.state, &mle.s_in, &mle.s_out];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let (batch, reductions) = prove_multi_batch_eval(&columns, &claims_by_column, channel);
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions
        .try_into()
        .expect("multi-batch returns one reduction per column");

    let proof = FixedFieldHashProofKillShot {
        kill_shot: BlockSpineKillShotProof { main, shift },
        chain,
        batch,
        n_claims: inputs.len(),
        n_fields: params.n_fields,
        num_vars: mle.num_vars,
        live_slots: mle.live_slots,
    };
    let reductions = FixedFieldHashReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

pub fn verify_fixed_field_hash_killshot<T: FiatShamir<Block128>>(
    params: FixedFieldHashParams,
    proof: &FixedFieldHashProofKillShot,
    inputs: &[FixedFieldHashInputs],
    channel: &mut T,
) -> Option<FixedFieldHashReductions> {
    if !validate_inputs(params, inputs)
        || proof.n_claims != inputs.len()
        || proof.n_fields != params.n_fields
        || proof.live_slots != inputs.len() * params.n_blocks()
    {
        return None;
    }
    let expected_num_vars = crate::block_spine::num_vars_for(proof.live_slots);
    if proof.num_vars != expected_num_vars {
        return None;
    }

    absorb_public_batch(params, channel, inputs);

    let main_red = verify_block_spine_unified(
        &proof.kill_shot.main,
        proof.num_vars,
        proof.live_slots,
        channel,
    )?;
    let shift_red =
        verify_block_spine_shift(&proof.kill_shot.shift, &main_red, proof.num_vars, channel)?;

    let chain_claims = claim_chain_claims(params, inputs, proof.num_vars);
    let chain_red = verify_linear_eval_prebound(
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        params.relation_tag,
        channel,
    )?;

    let state_claims = vec![
        EvalClaim {
            point: main_red.r_prime,
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
        },
    ];
    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];
    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let reductions =
        verify_multi_batch_eval(&proof.batch, &claims_by_column, proof.num_vars, channel)?;
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions.try_into().ok()?;

    Some(FixedFieldHashReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

pub fn discharge_fixed_field_hash_reductions_native(
    params: FixedFieldHashParams,
    inputs: &[FixedFieldHashInputs],
    reductions: &FixedFieldHashReductions,
) -> bool {
    let Some(slot_state_ins) = evaluate_claims(params, inputs) else {
        return false;
    };
    crate::block_spine::discharge_block_spine_batch_reductions_from_slot_state_ins_native(
        &slot_state_ins,
        &reductions.state,
        &reductions.sin,
        &reductions.sout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::native::compression::Poseidon2bSponge;
    use noid_poseidon2b::native::domain::TAG_HISTPRF;

    fn input(seed: u128, n_fields: usize) -> FixedFieldHashInputs {
        let fields: Vec<Block128> = (0..n_fields)
            .map(|i| Block128::from(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) + i as u128))
            .collect();
        let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
        for pair in fields.chunks_exact(2) {
            sponge.absorb_pair(pair[0], pair[1]);
        }
        let digest = sponge.finalize_no_pad();
        let expected_digest = [
            Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
            Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
        ];
        FixedFieldHashInputs {
            fields,
            expected_digest,
        }
    }

    #[test]
    fn fixed_field_hash_roundtrip_for_history_schedules() {
        let pcd_params = FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, 56)
            .expect("valid PCD schedule");
        let arc_params = FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, 14)
            .expect("valid ARC schedule");
        assert_ne!(pcd_params.relation_tag, arc_params.relation_tag);

        for n_fields in [14usize, 56usize] {
            let params = FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, n_fields)
                .expect("valid fixed schedule");
            let inputs = vec![input(1, n_fields), input(2, n_fields)];
            let mut ch_p = Poseidon2bChannel::new();
            let (proof, reductions) = prove_fixed_field_hash_killshot(params, &inputs, &mut ch_p);

            let mut ch_v = Poseidon2bChannel::new();
            let verified = verify_fixed_field_hash_killshot(params, &proof, &inputs, &mut ch_v)
                .expect("fixed-field hash proof verifies");
            assert_eq!(verified, reductions);
            assert!(discharge_fixed_field_hash_reductions_native(
                params, &inputs, &verified
            ));
        }
    }

    #[test]
    fn fixed_field_hash_rejects_tamper() {
        let params =
            FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, 14).expect("params");
        let inputs = vec![input(9, 14)];
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_fixed_field_hash_killshot(params, &inputs, &mut ch_p);
        let mut bad = inputs.clone();
        bad[0].expected_digest[1] += Block128::ONE;
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_fixed_field_hash_killshot(params, &proof, &bad, &mut ch_v).is_none());
    }

    #[test]
    fn fixed_field_hash_byte_len_counts_compressed_round_fields_exactly() {
        let params =
            FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, 4).expect("params");
        let inputs = vec![input(9, 4), input(10, 4)];
        let mut channel = Poseidon2bChannel::new();
        let (proof, _) = prove_fixed_field_hash_killshot(params, &inputs, &mut channel);

        let main_round_fields = proof
            .kill_shot
            .main
            .round_polys
            .iter()
            .map(|round| round.coeffs_no_linear.len())
            .sum::<usize>();
        let shift_round_fields = proof
            .kill_shot
            .shift
            .round_polys
            .iter()
            .map(|round| round.coeffs_no_linear.len())
            .sum::<usize>();
        assert!(proof
            .kill_shot
            .main
            .round_polys
            .iter()
            .all(|round| round.coeffs_no_linear.len() == 9));
        assert!(proof
            .kill_shot
            .shift
            .round_polys
            .iter()
            .all(|round| round.coeffs_no_linear.len() == 2));

        let exact = (main_round_fields + shift_round_fields + 12 + 3) * 16
            + proof.chain.byte_len()
            + proof.batch.byte_len();
        assert_eq!(proof.byte_len(), exact);
        assert_eq!(proof.byte_len(), 16 * (15 * proof.num_vars + 19));
    }
}
