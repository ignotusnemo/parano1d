// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production authorization-capsule algebra composition.
//!
//! This is the first fixed-shape wrapper which joins the complete Owner
//! AuthGKR verifier, the transparent post-claim relation, and Phase A.  It
//! deliberately excludes transcript replay, commitment openings, and Phase B;
//! those regions own the dynamic inputs supplied here.
//!
//! The component boundary is alias-only:
//!
//! - Owner's returned LOW-to-HIGH terminal point is the post-claim `r`;
//! - the same `rho`, five padded operand claims, and two mask claims are consumed by
//!   Owner and the post-claim relation;
//! - reversed Phase-A round challenges are both the post-claim `s` and the
//!   terminal point returned by Phase A; and
//! - the post-claim outputs `bank_claim` and `terminal_relation_value` are
//!   passed directly into Phase A.
//!
//! No equality-copy rows are inserted at those boundaries.  Consequently the
//! exact incremental ledger is the sum of the three component ledgers.

use noid_gkr::zk_auth_capsule::ZK_AUTH_CAPSULE_BANK_VARS;
use noid_tx::OwnerAuthorizationVersion;

use super::zk_auth_terminal::AuthCapsuleTerminalOperandClaimsTrace;
use super::zk_mlecheck::ZkMleCheckRoundProofTrace;
use super::zk_owner_verifier::{
    verify_zk_owner_trace, ZkOwnerVerifierTraceError, ZkOwnerVerifierTraceInput,
    ZkOwnerVerifierTraceOutput, ZK_OWNER_VERIFIER_TRACE_ROWS,
};
use super::zk_phase_a::{
    verify_zk_phase_a_trace, ZkPhaseATraceError, ZkPhaseATraceInput, ZkPhaseATraceOutput,
    ZkPhaseATraceRound, ZK_PHASE_A_ROUNDS, ZK_PHASE_A_TRACE_ROWS,
};
use super::zk_post_claim_relation::{
    ZkPostClaimRelationTraceError, ZkPostClaimRelationTraceInput, ZkPostClaimRelationTraceOutput,
    ZK_POST_CLAIM_RELATION_TRACE_ROWS,
};
use super::{ExtExpr, FieldR1csBuilder, LinExpr};

/// Exact incremental ledger after all caller-owned dynamic inputs are
/// allocated.  Alias-only component boundaries add no rows.
pub const ZK_AUTH_COMPOSITION_TRACE_ROWS: usize =
    ZK_OWNER_VERIFIER_TRACE_ROWS + ZK_POST_CLAIM_RELATION_TRACE_ROWS + ZK_PHASE_A_TRACE_ROWS;

const _: () = assert!(ZK_AUTH_CAPSULE_BANK_VARS == 11);
const _: () = assert!(ZK_PHASE_A_ROUNDS == ZK_AUTH_CAPSULE_BANK_VARS);
const _: () = assert!(ZK_OWNER_VERIFIER_TRACE_ROWS == 871);
const _: () = assert!(ZK_POST_CLAIM_RELATION_TRACE_ROWS == 893);
const _: () = assert!(ZK_PHASE_A_TRACE_ROWS == 88);
const _: () = assert!(ZK_AUTH_COMPOSITION_TRACE_ROWS == 1_852);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthCompositionTraceError {
    Owner(ZkOwnerVerifierTraceError),
    PostClaim(ZkPostClaimRelationTraceError),
    PhaseA(ZkPhaseATraceError),
}

impl From<ZkOwnerVerifierTraceError> for ZkAuthCompositionTraceError {
    fn from(value: ZkOwnerVerifierTraceError) -> Self {
        Self::Owner(value)
    }
}

impl From<ZkPostClaimRelationTraceError> for ZkAuthCompositionTraceError {
    fn from(value: ZkPostClaimRelationTraceError) -> Self {
        Self::PostClaim(value)
    }
}

impl From<ZkPhaseATraceError> for ZkAuthCompositionTraceError {
    fn from(value: ZkPhaseATraceError) -> Self {
        Self::PhaseA(value)
    }
}

/// Dynamic expressions for one authorization capsule.
///
/// There are intentionally no caller-supplied fields for Owner's terminal
/// point `r`, Phase A's terminal point `s`, the bank claim, or `t(s)`.  Each
/// is derived once and handed to its consumer as the same [`LinExpr`].
#[derive(Clone, Debug)]
pub struct ZkAuthCompositionTraceInput {
    /// AuthGKR input point in canonical LOW-to-HIGH order.
    pub rho: [ExtExpr; ZK_AUTH_CAPSULE_BANK_VARS],
    pub mask_mle_at_input: ExtExpr,
    pub mask_final_at_terminal: ExtExpr,
    pub lambda: ExtExpr,
    /// Owner MLE-check rounds in transcript HIGH-to-LOW order.
    pub owner_rounds: [ZkMleCheckRoundProofTrace; ZK_AUTH_CAPSULE_BANK_VARS],
    /// Owner round challenges `[r_10, ..., r_0]`.
    pub owner_challenges_high_to_low: [ExtExpr; ZK_AUTH_CAPSULE_BANK_VARS],
    pub terminal_operands: AuthCapsuleTerminalOperandClaimsTrace,
    /// Public output-address lanes; the capacity-IV lanes are constants in
    /// the post-claim relation.
    pub expected_address: [LinExpr; 2],
    /// Post-claim RLC challenge, sampled after all eleven claims.
    pub eta: ExtExpr,
    /// `sigma = <C,t>`, transcript-bound before `gamma` is sampled.
    pub companion_claim: ExtExpr,
    pub gamma: ExtExpr,
    /// Phase-A challenges `[s_10, ..., s_0]`.
    pub phase_a_challenges_high_to_low: [ExtExpr; ZK_PHASE_A_ROUNDS],
    pub phase_a_rounds: [ZkPhaseATraceRound; ZK_PHASE_A_ROUNDS],
    /// Phase-B-linked `O_gamma(s)` value `v`.
    pub terminal_oracle_value: ExtExpr,
}

/// Component outputs retained for the later transcript and Phase-B wrapper.
#[derive(Clone, Debug)]
pub struct ZkAuthCompositionTraceOutput {
    pub owner: ZkOwnerVerifierTraceOutput,
    pub post_claim: ZkPostClaimRelationTraceOutput,
    pub phase_a: ZkPhaseATraceOutput,
}

/// Compose one complete disconnected authorization algebra instance.
///
/// With well-formed dynamic inputs this appends exactly
/// [`ZK_AUTH_COMPOSITION_TRACE_ROWS`] rows.  The construction order follows
/// the protocol dependency graph: Owner, post-claim relation, then Phase A.
pub fn verify_zk_auth_composition_trace(
    b: &mut FieldR1csBuilder,
    input: &ZkAuthCompositionTraceInput,
) -> Result<ZkAuthCompositionTraceOutput, ZkAuthCompositionTraceError> {
    verify_zk_auth_composition_trace_for_version(b, input, OwnerAuthorizationVersion::V4)
}

pub const fn zk_auth_composition_rows_for_version(version: OwnerAuthorizationVersion) -> usize {
    ZK_OWNER_VERIFIER_TRACE_ROWS
        + super::zk_post_claim_relation::zk_post_claim_relation_rows_for_version(version)
        + ZK_PHASE_A_TRACE_ROWS
}

pub fn verify_zk_auth_composition_trace_for_version(
    b: &mut FieldR1csBuilder,
    input: &ZkAuthCompositionTraceInput,
    version: OwnerAuthorizationVersion,
) -> Result<ZkAuthCompositionTraceOutput, ZkAuthCompositionTraceError> {
    let trace_start = b.num_wires();

    let owner_input = ZkOwnerVerifierTraceInput {
        rho: input.rho.clone(),
        mask_mle_at_input: input.mask_mle_at_input.clone(),
        mask_final_at_terminal: input.mask_final_at_terminal.clone(),
        lambda: input.lambda.clone(),
        rounds: input.owner_rounds.clone(),
        challenges_high_to_low: input.owner_challenges_high_to_low.clone(),
        terminal_operands: input.terminal_operands.clone(),
    };
    let owner = verify_zk_owner_trace(b, &owner_input)?;

    // These are aliases of the exact Phase-A challenge expressions.  The
    // Phase-A verifier independently returns the same reversal below.
    let phase_a_terminal_point: [ExtExpr; ZK_PHASE_A_ROUNDS] =
        std::array::from_fn(|low_variable| {
            input.phase_a_challenges_high_to_low[ZK_PHASE_A_ROUNDS - 1 - low_variable].clone()
        });
    let terminal_operand_claims = [
        input.terminal_operands.increment.clone(),
        input.terminal_operands.lane[0].clone(),
        input.terminal_operands.lane[1].clone(),
        input.terminal_operands.lane[2].clone(),
        input.terminal_operands.lane[3].clone(),
    ];
    let post_claim_input = ZkPostClaimRelationTraceInput {
        input_point: input.rho.clone(),
        auth_terminal_point: owner.terminal_point.clone(),
        phase_a_terminal_point: phase_a_terminal_point.clone(),
        eta: input.eta.clone(),
        terminal_operand_claims,
        mask_mle_at_input: input.mask_mle_at_input.clone(),
        mask_final_at_terminal: input.mask_final_at_terminal.clone(),
        expected_address: input.expected_address.clone(),
    };
    let post_claim = super::zk_post_claim_relation::build_zk_post_claim_relation_trace_for_version(
        b,
        &post_claim_input,
        version,
    )?;

    let phase_a_input = ZkPhaseATraceInput {
        bank_claim: post_claim.bank_claim.clone(),
        companion_claim: input.companion_claim.clone(),
        gamma: input.gamma.clone(),
        challenges_high_to_low: input.phase_a_challenges_high_to_low.clone(),
        rounds: input.phase_a_rounds.clone(),
        terminal_relation_value: post_claim.terminal_relation_value.clone(),
        terminal_oracle_value: input.terminal_oracle_value.clone(),
    };
    let phase_a = verify_zk_phase_a_trace(b, &phase_a_input)?;

    // Structural, zero-row assertions: component hand-offs must be the same
    // expressions, not newly allocated values constrained equal afterwards.
    assert_eq!(owner.terminal_point, post_claim_input.auth_terminal_point);
    assert_eq!(phase_a.terminal_point, phase_a_terminal_point);
    assert_eq!(phase_a_input.bank_claim, post_claim.bank_claim);
    assert_eq!(
        phase_a.terminal_relation_value,
        post_claim.terminal_relation_value
    );
    assert_eq!(phase_a.terminal_oracle_value, input.terminal_oracle_value);
    debug_assert_eq!(
        b.num_wires() - trace_start,
        zk_auth_composition_rows_for_version(version),
        "authorization composition row ledger drifted"
    );

    Ok(ZkAuthCompositionTraceOutput {
        owner,
        post_claim,
        phase_a,
    })
}

#[cfg(test)]
mod tests {
    use noid_core::mle::evaluate::evaluate_slice;
    use noid_core::{Block128, Block256, TowerField};
    use noid_fri_binius::zk_phase_a::{
        prove_phase_a, verify_phase_a, ZkPhaseARoundProof, PHASE_A_ORACLE_LEN,
    };
    use noid_gkr::layers::evaluate_permutation;
    use noid_gkr::zk_auth_capsule::{
        build_explicit_mlecheck_carrier, build_post_claim_relation, state_cell_index,
        AuthCapsuleBoundaryPublic, AuthCapsuleTerminalOperandClaims, ZkAuthCapsuleBankView,
        ZK_AUTH_CAPSULE_BANK_LEN, ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET,
        ZK_AUTH_CAPSULE_PCS_COINS_OFFSET, ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET,
    };
    use noid_gkr::zk_mlecheck::ZkMleCheckRoundProof;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};

    use super::super::{alloc_block, alloc_block256, flat_of, test_support::tower_value_ext, F128};
    use super::*;

    const DYNAMIC_INPUT_ROWS: usize = 2
        * (ZK_AUTH_CAPSULE_BANK_VARS
            + 2
            + 1
            + ZK_AUTH_CAPSULE_BANK_VARS * 10
            + ZK_AUTH_CAPSULE_BANK_VARS
            + 5
            + 1
            + 1
            + 1
            + ZK_PHASE_A_ROUNDS
            + ZK_PHASE_A_ROUNDS * 2
            + 1)
        + 2;
    const FIXTURE_USEFUL_ROWS: usize = 1 + DYNAMIC_INPUT_ROWS + ZK_AUTH_COMPOSITION_TRACE_ROWS;

    fn elem(index: usize, domain: u128, salt: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((index * 19 + 7) % 127) as u32)
                ^ salt.rotate_left(((index * 3 + 1) % 127) as u32)
                ^ (index as u128 + 5).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    fn ext_elem(index: usize, domain: u128, salt: u128) -> Block256 {
        Block256::new(
            elem(index, domain, salt),
            elem(index + 137, domain ^ 0xC1_256, salt.rotate_left(59)),
        )
    }

    fn point(domain: u128, salt: u128) -> [Block256; ZK_AUTH_CAPSULE_BANK_VARS] {
        std::array::from_fn(|index| ext_elem(index + 29, domain, salt))
    }

    #[derive(Clone)]
    struct NativeCase {
        rho: [Block256; ZK_AUTH_CAPSULE_BANK_VARS],
        mask_mle_at_input: Block256,
        mask_final_at_terminal: Block256,
        lambda: Block256,
        owner_rounds: [ZkMleCheckRoundProof<Block256>; ZK_AUTH_CAPSULE_BANK_VARS],
        owner_challenges: [Block256; ZK_AUTH_CAPSULE_BANK_VARS],
        terminal_operands: AuthCapsuleTerminalOperandClaims<Block256>,
        owner_terminal_point: [Block256; ZK_AUTH_CAPSULE_BANK_VARS],
        owner_main_final: Block256,
        expected_address: [Block128; 2],
        eta: Block256,
        bank_claim: Block256,
        companion_claim: Block256,
        gamma: Block256,
        phase_a_challenges: [Block256; ZK_PHASE_A_ROUNDS],
        phase_a_rounds: [ZkPhaseARoundProof<Block256>; ZK_PHASE_A_ROUNDS],
        phase_a_terminal_point: [Block256; ZK_PHASE_A_ROUNDS],
        terminal_relation_value: Block256,
        terminal_oracle_value: Block256,
        initial_claim: Block256,
    }

    /// Build the actual Poseidon state bank, explicit AuthGKR carrier,
    /// transparent post-claim relation, fresh companion, and native Phase A.
    fn native_case(salt: u128) -> NativeCase {
        let iv = capacity_iv(TAG_ADDRFIX);
        let permutation = evaluate_permutation([
            elem(0, 0x5EC2_E7, salt),
            elem(1, 0x5EC2_E7, salt ^ 0x10),
            iv[0],
            iv[1],
        ]);
        let expected_address = [permutation.final_state()[0], permutation.final_state()[1]];
        let mut bank = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
        for (round, row) in permutation.state.iter().enumerate() {
            for (lane, value) in row.iter().copied().enumerate() {
                bank[state_cell_index(round, lane).unwrap()] = value;
            }
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .take(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET)
            .skip(ZK_AUTH_CAPSULE_PCS_COINS_OFFSET)
        {
            *cell = elem(index, 0xC01A_5, salt ^ 0x20);
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .take(ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET)
            .skip(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET)
        {
            *cell = elem(index, 0x11B2_A, salt ^ 0x30);
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .skip(ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET)
        {
            *cell = elem(index, 0xA771_A6, salt ^ 0x40);
        }
        let bank_view = ZkAuthCapsuleBankView::checked(&bank).expect("bank shape");

        let rho = point(0x1A90_7, salt ^ 0x50);
        let owner_challenges = point(0xC4A1_1, salt ^ 0x60);
        let mut lambda = ext_elem(71, 0x1A4B_DA, salt ^ 0x70);
        if lambda == Block256::ZERO {
            lambda = Block256::ONE;
        }
        let carrier = build_explicit_mlecheck_carrier(bank_view, rho, lambda, owner_challenges)
            .expect("real explicit Owner carrier");

        let mut eta = ext_elem(73, 0xE7A0, salt ^ 0x80);
        if eta == Block256::ZERO {
            eta = Block256::ONE;
        }
        let relation = build_post_claim_relation(
            &rho,
            &carrier.terminal_point,
            AuthCapsuleBoundaryPublic::canonical(expected_address),
            carrier.post_claims(),
            eta,
        )
        .expect("native post-claim relation");
        assert!(relation.verify(bank_view));

        // This companion uses a disjoint deterministic domain solely to make
        // the fixture reproducible.  It is not copied from or derived from B.
        let companion: Vec<Block256> = (0..PHASE_A_ORACLE_LEN)
            .map(|index| ext_elem(index, 0xC09A_91, salt ^ 0x90))
            .collect();
        assert!(
            companion
                .iter()
                .zip(&bank)
                .any(|(&companion, &bank)| companion != Block256::from(bank)),
            "fixture companion must be independent"
        );
        let phase_a_challenges = point(0x5A11_CE, salt ^ 0xA0);
        let mut gamma = ext_elem(79, 0x6A77_A, salt ^ 0xB0);
        if gamma == Block256::ZERO || gamma == Block256::ONE {
            gamma += Block256::from(2u128);
        }
        let phase_a = prove_phase_a(
            &bank,
            &companion,
            &relation.weights,
            gamma,
            &phase_a_challenges,
        )
        .expect("native Phase A");
        let verified = verify_phase_a(
            &phase_a.proof,
            phase_a.relation_claims,
            &relation.weights,
            gamma,
            &phase_a_challenges,
            phase_a.terminal_oracle_value,
        )
        .expect("native Phase A verifies");
        assert_eq!(
            phase_a.relation_claims.bank,
            relation.expected_inner_product
        );
        assert_eq!(
            verified.terminal_relation_value,
            evaluate_slice(&relation.weights, &phase_a.terminal_point)
        );

        NativeCase {
            rho,
            mask_mle_at_input: carrier.mask_mle_at_input,
            mask_final_at_terminal: carrier.mask_final_at_terminal,
            lambda,
            owner_rounds: carrier
                .round_proofs
                .try_into()
                .expect("exact eleven Owner rounds"),
            owner_challenges,
            terminal_operands: carrier.terminal_operands,
            owner_terminal_point: carrier.terminal_point,
            owner_main_final: carrier.main_final_at_terminal,
            expected_address,
            eta,
            bank_claim: relation.expected_inner_product,
            companion_claim: phase_a.relation_claims.companion,
            gamma,
            phase_a_challenges,
            phase_a_rounds: phase_a.proof.rounds,
            phase_a_terminal_point: phase_a.terminal_point,
            terminal_relation_value: verified.terminal_relation_value,
            terminal_oracle_value: phase_a.terminal_oracle_value,
            initial_claim: phase_a.initial_claim,
        }
    }

    fn alloc_input(b: &mut FieldR1csBuilder, native: &NativeCase) -> ZkAuthCompositionTraceInput {
        ZkAuthCompositionTraceInput {
            rho: std::array::from_fn(|index| alloc_block256(b, native.rho[index])),
            mask_mle_at_input: alloc_block256(b, native.mask_mle_at_input),
            mask_final_at_terminal: alloc_block256(b, native.mask_final_at_terminal),
            lambda: alloc_block256(b, native.lambda),
            owner_rounds: std::array::from_fn(|round| ZkMleCheckRoundProofTrace {
                coeffs_without_constant: std::array::from_fn(|coefficient| {
                    alloc_block256(
                        b,
                        native.owner_rounds[round].coeffs_without_constant[coefficient],
                    )
                }),
            }),
            owner_challenges_high_to_low: std::array::from_fn(|round| {
                alloc_block256(b, native.owner_challenges[round])
            }),
            terminal_operands: AuthCapsuleTerminalOperandClaimsTrace {
                increment: alloc_block256(b, native.terminal_operands.increment),
                lane: std::array::from_fn(|lane| {
                    alloc_block256(b, native.terminal_operands.lane[lane])
                }),
            },
            expected_address: std::array::from_fn(|lane| {
                alloc_block(b, native.expected_address[lane])
            }),
            eta: alloc_block256(b, native.eta),
            companion_claim: alloc_block256(b, native.companion_claim),
            gamma: alloc_block256(b, native.gamma),
            phase_a_challenges_high_to_low: std::array::from_fn(|round| {
                alloc_block256(b, native.phase_a_challenges[round])
            }),
            phase_a_rounds: std::array::from_fn(|round| ZkPhaseATraceRound {
                at_one: alloc_block256(b, native.phase_a_rounds[round].at_one),
                at_infinity: alloc_block256(b, native.phase_a_rounds[round].at_infinity),
            }),
            terminal_oracle_value: alloc_block256(b, native.terminal_oracle_value),
        }
    }

    struct BuiltCase {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        trace_rows: usize,
        owner_terminal_point: [Block256; ZK_AUTH_CAPSULE_BANK_VARS],
        phase_a_terminal_point: [Block256; ZK_PHASE_A_ROUNDS],
        owner_main_final: Block256,
        bank_claim: Block256,
        terminal_relation_value: Block256,
        initial_claim: Block256,
        bank_internal_wire: usize,
        terminal_relation_internal_wire: usize,
    }

    fn internal_wire(expression: &ExtExpr, first_internal_wire: usize) -> usize {
        expression
            .lo
            .terms
            .iter()
            .chain(expression.hi.terms.iter())
            .map(|(wire, _)| *wire as usize)
            .filter(|wire| *wire >= first_internal_wire)
            .max()
            .expect("derived hand-off must contain an internal wire")
    }

    fn build_case(native: &NativeCase) -> Result<BuiltCase, ZkAuthCompositionTraceError> {
        let mut b = FieldR1csBuilder::new();
        let input = alloc_input(&mut b, native);
        assert_eq!(b.num_wires(), 1 + DYNAMIC_INPUT_ROWS);
        let first_internal_wire = b.num_wires();
        let output = verify_zk_auth_composition_trace(&mut b, &input)?;
        let trace_rows = b.num_wires() - first_internal_wire;

        let owner_terminal_point =
            std::array::from_fn(|index| tower_value_ext(&b, &output.owner.terminal_point[index]));
        let phase_a_terminal_point =
            std::array::from_fn(|index| tower_value_ext(&b, &output.phase_a.terminal_point[index]));
        let owner_main_final = tower_value_ext(&b, &output.owner.main_eval);
        let bank_claim = tower_value_ext(&b, &output.post_claim.bank_claim);
        let terminal_relation_value =
            tower_value_ext(&b, &output.post_claim.terminal_relation_value);
        let initial_claim = tower_value_ext(&b, &output.phase_a.initial_claim);
        let bank_internal_wire = internal_wire(&output.post_claim.bank_claim, first_internal_wire);
        let terminal_relation_internal_wire = internal_wire(
            &output.post_claim.terminal_relation_value,
            first_internal_wire,
        );
        let (r1cs, witness) = b.build();
        Ok(BuiltCase {
            r1cs,
            witness,
            trace_rows,
            owner_terminal_point,
            phase_a_terminal_point,
            owner_main_final,
            bank_claim,
            terminal_relation_value,
            initial_claim,
            bank_internal_wire,
            terminal_relation_internal_wire,
        })
    }

    fn assert_rejected(candidate: &NativeCase, name: &str) {
        let built = build_case(candidate).expect("tamper retains fixed shape");
        assert_eq!(built.trace_rows, ZK_AUTH_COMPOSITION_TRACE_ROWS);
        assert!(
            !built.r1cs.satisfies(&built.witness),
            "accepted {name} tamper"
        );
    }

    #[test]
    fn complete_composition_matches_real_native_fixture_and_exact_ledger() {
        let native = native_case(0xA11C_E001);
        let built = build_case(&native).expect("honest complete composition");
        assert!(built.r1cs.satisfies(&built.witness));
        assert_eq!(ZK_OWNER_VERIFIER_TRACE_ROWS, 871);
        assert_eq!(ZK_POST_CLAIM_RELATION_TRACE_ROWS, 893);
        assert_eq!(ZK_PHASE_A_TRACE_ROWS, 88);
        assert_eq!(ZK_AUTH_COMPOSITION_TRACE_ROWS, 1_852);
        assert_eq!(built.trace_rows, ZK_AUTH_COMPOSITION_TRACE_ROWS);
        assert_eq!(built.r1cs.useful_rows, FIXTURE_USEFUL_ROWS);
        assert_eq!(built.owner_terminal_point, native.owner_terminal_point);
        assert_eq!(built.phase_a_terminal_point, native.phase_a_terminal_point);
        assert_eq!(built.owner_main_final, native.owner_main_final);
        assert_eq!(built.bank_claim, native.bank_claim);
        assert_eq!(
            built.terminal_relation_value,
            native.terminal_relation_value
        );
        assert_eq!(built.initial_claim, native.initial_claim);
    }

    #[test]
    fn shared_r_operand_rho_and_claim_order_splices_are_rejected() {
        let honest = native_case(0xA11C_E002);

        let mut r = honest.clone();
        r.owner_challenges[4] += Block256::ONE;
        assert_rejected(&r, "Owner r");

        let mut state = honest.clone();
        state.terminal_operands.lane[1] += Block256::ONE;
        assert_rejected(&state, "shared terminal state");

        let mut rho = honest.clone();
        rho.rho[7] += Block256::ONE;
        assert_rejected(&rho, "shared rho");

        let mut order = honest;
        order.terminal_operands.lane.swap(0, 3);
        assert_rejected(&order, "terminal claim order");
    }

    #[test]
    fn post_claim_phase_a_bank_t_sigma_v_address_and_eta_splices_are_rejected() {
        let honest = native_case(0xA11C_E003);
        let other = native_case(0xA11C_E103);

        // A Phase-A proof from another complete relation simultaneously
        // splices the derived bank claim and t(s) boundary.
        let mut bank_and_t = honest.clone();
        bank_and_t.companion_claim = other.companion_claim;
        bank_and_t.gamma = other.gamma;
        bank_and_t.phase_a_challenges = other.phase_a_challenges;
        bank_and_t.phase_a_rounds = other.phase_a_rounds;
        bank_and_t.terminal_oracle_value = other.terminal_oracle_value;
        assert_rejected(&bank_and_t, "foreign bank/t(s) Phase-A splice");

        let mut sigma = honest.clone();
        sigma.companion_claim += Block256::ONE;
        assert_rejected(&sigma, "sigma");

        let mut v = honest.clone();
        v.terminal_oracle_value += Block256::ONE;
        assert_rejected(&v, "v");

        let mut address = honest.clone();
        address.expected_address[1] += Block128::ONE;
        assert_rejected(&address, "address");

        let mut eta = honest;
        eta.eta += Block256::ONE;
        if eta.eta == Block256::ZERO {
            eta.eta += Block256::from(2u128);
        }
        assert_rejected(&eta, "eta");
    }

    #[test]
    fn lambda_gamma_and_high_to_low_order_tampers_are_rejected() {
        let honest = native_case(0xA11C_E004);

        let mut lambda = honest.clone();
        lambda.lambda += Block256::ONE;
        if lambda.lambda == Block256::ZERO {
            lambda.lambda += Block256::from(2u128);
        }
        assert_rejected(&lambda, "lambda");

        let mut gamma = honest.clone();
        gamma.gamma += Block256::ONE;
        if gamma.gamma == Block256::ZERO || gamma.gamma == Block256::ONE {
            gamma.gamma += Block256::from(2u128);
        }
        assert_rejected(&gamma, "gamma");

        let mut owner_order = honest.clone();
        owner_order.owner_challenges.reverse();
        assert_rejected(&owner_order, "Owner challenge order");

        let mut phase_order = honest;
        phase_order.phase_a_challenges.reverse();
        assert_rejected(&phase_order, "Phase-A challenge order");
    }

    #[test]
    fn derived_bank_and_terminal_relation_cannot_be_witness_spliced() {
        let native = native_case(0xA11C_E005);
        let built = build_case(&native).expect("honest composition");
        assert!(built.r1cs.satisfies(&built.witness));

        let mut bank = built.witness.clone();
        bank[built.bank_internal_wire] += F128::ONE;
        assert!(
            !built.r1cs.satisfies(&bank),
            "derived bank claim internal wire was free"
        );

        let mut terminal = built.witness.clone();
        terminal[built.terminal_relation_internal_wire] += F128::ONE;
        assert!(
            !built.r1cs.satisfies(&terminal),
            "derived t(s) internal wire was free"
        );
    }

    #[test]
    fn complete_composition_matrix_is_content_invariant() {
        let left = build_case(&native_case(0xA11C_E006)).expect("left composition");
        let right = build_case(&native_case(0xA11C_E007)).expect("right composition");
        assert!(left.r1cs.satisfies(&left.witness));
        assert!(right.r1cs.satisfies(&right.witness));
        assert_eq!(left.trace_rows, ZK_AUTH_COMPOSITION_TRACE_ROWS);
        assert_eq!(right.trace_rows, ZK_AUTH_COMPOSITION_TRACE_ROWS);
        assert_eq!(left.r1cs.useful_rows, FIXTURE_USEFUL_ROWS);
        assert_eq!(right.r1cs.useful_rows, FIXTURE_USEFUL_ROWS);
        assert_eq!(
            left.r1cs.structural_statement_digest(),
            right.r1cs.structural_statement_digest()
        );
    }

    #[test]
    fn dynamic_fields_are_not_matrix_constants() {
        let native = native_case(0xA11C_E008);
        let mut b = FieldR1csBuilder::new();
        let mut input = alloc_input(&mut b, &native);
        input.expected_address[0] = LinExpr::constant(flat_of(native.expected_address[0]));
        let before = b.num_wires();
        assert!(matches!(
            verify_zk_auth_composition_trace(&mut b, &input),
            Err(ZkAuthCompositionTraceError::PostClaim(
                ZkPostClaimRelationTraceError::DynamicInputIsConstant { .. }
            ))
        ));
        // Owner precedes the post-claim component, so its exact rows are
        // present; the failing component itself remains atomic.
        assert_eq!(b.num_wires() - before, ZK_OWNER_VERIFIER_TRACE_ROWS);
    }
}
