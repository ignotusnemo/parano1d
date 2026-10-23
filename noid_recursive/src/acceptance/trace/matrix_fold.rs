//! Trace twin of `noid_ivc_core::matrix_claim::verify_matrix_claim_fold`
//! — the accumulator step of the self-verification chain.
//!
//! Line-by-line transliteration: same header absorbs, same γ/δ samples,
//! degree-2 compressed rounds (`[c_0, c_2]`, the linear coefficient
//! reconstructed from the running claim), and the two terminal pins. The
//! matrix never appears: the terminals evaluate the CHALLENGE-derived
//! weights (λ window at `z_skip`, eq of the statement/fold points, the
//! z_partial window, the α stack-bit weight) against prover-supplied G
//! and final-evaluation wires, and the outgoing plain claim
//! `M̂~(ρ ‖ σ) = final` is returned for the caller's IO exposure.

use noid_ivc_core::field_circuit::FsChannelOps;
#[cfg(test)]
use noid_ivc_core::field_circuit::FsChannelTrace;
use noid_ivc_core::matrix_claim::c1::{C1MatrixAccClaim, C1MatrixFoldProof};
use noid_ivc_core::matrix_claim::MatrixFoldProof;

use super::self_verify::{lagrange_weights_window_ext_trace, lagrange_weights_window_trace};
use super::{
    evaluate_slice_ext_trace, mul, mul_ext, pin_eq, pin_eq_ext, ExtExpr, FieldR1csBuilder, LinExpr,
    F128, F256,
};

/// A plain accumulated claim as expressions (`2·k_log + 1` coordinates).
#[derive(Clone)]
pub struct MatrixAccClaimTrace {
    pub point: Vec<LinExpr>,
    pub value: LinExpr,
}

impl MatrixAccClaimTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &noid_ivc_core::matrix_claim::MatrixAccClaim,
    ) -> Self {
        Self {
            point: native
                .point
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect(),
            value: LinExpr::from_wire(b.alloc_f128(native.value)),
        }
    }
}

/// The deferred lincheck claim as expressions (see
/// `matrix_claim::FreshLincheckClaim`).
pub struct FreshLincheckClaimTrace {
    pub alpha: LinExpr,
    pub z_skip: LinExpr,
    pub x_inner_rest: Vec<LinExpr>,
    pub r_inner_rest: Vec<LinExpr>,
    pub z_partial: Vec<LinExpr>,
    pub value: LinExpr,
}

/// Witness allocation of a [`MatrixFoldProof`].
pub struct MatrixFoldProofTrace {
    pub phase1_rounds: Vec<[LinExpr; 2]>,
    pub g_v: LinExpr,
    pub g_e: LinExpr,
    pub phase2_rounds: Vec<[LinExpr; 2]>,
    pub final_matrix_eval: LinExpr,
}

impl MatrixFoldProofTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &MatrixFoldProof, k_log: usize) -> Self {
        assert_eq!(native.phase1_rounds.len(), k_log + 1, "phase-1 rounds");
        assert_eq!(native.phase2_rounds.len(), k_log, "phase-2 rounds");
        let alloc = |b: &mut FieldR1csBuilder, v: F128| LinExpr::from_wire(b.alloc_f128(v));
        Self {
            phase1_rounds: native
                .phase1_rounds
                .iter()
                .map(|w| [alloc(b, w[0]), alloc(b, w[1])])
                .collect(),
            g_v: alloc(b, native.g_v),
            g_e: alloc(b, native.g_e),
            phase2_rounds: native
                .phase2_rounds
                .iter()
                .map(|w| [alloc(b, w[0]), alloc(b, w[1])])
                .collect(),
            final_matrix_eval: alloc(b, native.final_matrix_eval),
        }
    }
}

#[derive(Clone)]
pub struct C1MatrixAccClaimTrace {
    pub point: Vec<ExtExpr>,
    pub value: ExtExpr,
}

impl C1MatrixAccClaimTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &C1MatrixAccClaim) -> Self {
        Self {
            point: native
                .point
                .iter()
                .map(|&value| alloc_ext(b, value))
                .collect(),
            value: alloc_ext(b, native.value),
        }
    }
}

#[derive(Clone)]
pub struct C1FreshLincheckClaimTrace {
    pub alpha: ExtExpr,
    pub z_skip: ExtExpr,
    pub x_inner_rest: Vec<ExtExpr>,
    pub r_inner_rest: Vec<ExtExpr>,
    pub z_partial: Vec<ExtExpr>,
    pub value: ExtExpr,
}

pub struct C1MatrixFoldProofTrace {
    pub phase1_rounds: Vec<[ExtExpr; 2]>,
    pub g_v: ExtExpr,
    pub g_e: ExtExpr,
    pub phase2_rounds: Vec<[ExtExpr; 2]>,
    pub final_matrix_eval: ExtExpr,
}

fn alloc_ext(b: &mut FieldR1csBuilder, value: F256) -> ExtExpr {
    ExtExpr::new(
        LinExpr::from_wire(b.alloc_f128(value.lo)),
        LinExpr::from_wire(b.alloc_f128(value.hi)),
    )
}

impl C1MatrixFoldProofTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &C1MatrixFoldProof, k_log: usize) -> Self {
        assert_eq!(native.phase1_rounds.len(), k_log + 1);
        assert_eq!(native.phase2_rounds.len(), k_log);
        Self {
            phase1_rounds: native
                .phase1_rounds
                .iter()
                .map(|wire| [alloc_ext(b, wire[0]), alloc_ext(b, wire[1])])
                .collect(),
            g_v: alloc_ext(b, native.g_v),
            g_e: alloc_ext(b, native.g_e),
            phase2_rounds: native
                .phase2_rounds
                .iter()
                .map(|wire| [alloc_ext(b, wire[0]), alloc_ext(b, wire[1])])
                .collect(),
            final_matrix_eval: alloc_ext(b, native.final_matrix_eval),
        }
    }
}

/// eq of an expression point against another expression point (pairwise
/// closed form, 3 multiplications per coordinate).
fn eq_points_trace(b: &mut FieldR1csBuilder, x: &[LinExpr], y: &[LinExpr]) -> LinExpr {
    assert_eq!(x.len(), y.len());
    let one = LinExpr::constant(F128::ONE);
    let mut acc = LinExpr::constant(F128::ONE);
    for (a, c) in x.iter().zip(y.iter()) {
        let m1 = mul(b, a, c);
        let m2 = mul(b, &one.add(a), &one.add(c));
        let matched = m1.add(&m2);
        acc = mul(b, &acc, &matched);
    }
    acc
}

/// MLE of a small wire vector at an expression point: eq tensor of the
/// point (2^n − 1 multiplications) dotted with the values.
fn small_mle_eval_trace(
    b: &mut FieldR1csBuilder,
    values: &[LinExpr],
    point: &[LinExpr],
) -> LinExpr {
    assert_eq!(values.len(), 1usize << point.len());
    let eq = super::eq_ind_partial_eval_trace(b, point);
    let mut acc = LinExpr::zero();
    for (v, e) in values.iter().zip(eq.iter()) {
        acc = acc.add(&mul(b, v, e));
    }
    acc
}

fn compressed_deg2_round(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    claim: &LinExpr,
    wire: &[LinExpr; 2],
) -> (LinExpr, LinExpr) {
    ch.observe_f128_slice(b, wire);
    let c1 = claim.add(&wire[1]);
    let r = ch.sample_f128(b);
    let t = mul(b, &wire[1], &r);
    let t = mul(b, &t.add(&c1), &r);
    (t.add(&wire[0]), r)
}

fn eq_points_c1_trace(b: &mut FieldR1csBuilder, left: &[ExtExpr], right: &[ExtExpr]) -> ExtExpr {
    assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right)
        .fold(ExtExpr::one(), |product, (left, right)| {
            mul_ext(b, &product, &left.add(right).add_const(F256::ONE))
        })
}

fn compressed_deg2_round_c1(
    b: &mut FieldR1csBuilder,
    channel: &mut impl FsChannelOps,
    claim: &ExtExpr,
    wire: &[ExtExpr; 2],
) -> (ExtExpr, ExtExpr) {
    channel.observe_f256_slice(b, wire);
    let linear = claim.add(&wire[1]);
    let challenge = channel.sample_f256(b);
    let intermediate = mul_ext(b, &wire[1], &challenge).add(&linear);
    (
        mul_ext(b, &intermediate, &challenge).add(&wire[0]),
        challenge,
    )
}

/// Trace twin of `verify_matrix_claim_fold`. `gate` is an expression
/// (the link computes it as `1 + g_prev` from the previous envelope);
/// the fold transcript runs on the caller-provided channel.
#[allow(clippy::too_many_arguments)]
pub fn verify_matrix_claim_fold_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    k_log: usize,
    k_skip: usize,
    fresh: &FreshLincheckClaimTrace,
    incoming: &MatrixAccClaimTrace,
    gate: &LinExpr,
    proof: &MatrixFoldProofTrace,
) -> MatrixAccClaimTrace {
    assert_eq!(fresh.x_inner_rest.len(), k_log - k_skip);
    assert_eq!(fresh.r_inner_rest.len(), k_log - k_skip);
    assert_eq!(fresh.z_partial.len(), 1usize << k_skip);
    assert_eq!(incoming.point.len(), 2 * k_log + 1);

    // Header (mirror of absorb_fold_header).
    ch.observe_label(b, b"history-matrix-claim-fold-v0");
    ch.observe_f128(b, &fresh.alpha);
    ch.observe_f128(b, &fresh.z_skip);
    ch.observe_f128_slice(b, &fresh.x_inner_rest);
    ch.observe_f128_slice(b, &fresh.r_inner_rest);
    ch.observe_f128_slice(b, &fresh.z_partial);
    ch.observe_f128(b, &fresh.value);
    ch.observe_f128_slice(b, &incoming.point);
    ch.observe_f128(b, &incoming.value);
    ch.observe_f128(b, gate);
    let gamma = ch.sample_f128(b);
    let gg = mul(b, &gamma, gate);

    let (p_in_row, p_in_col) = incoming.point.split_at(k_log + 1);

    // Phase 1.
    let ggw = mul(b, &gg, &incoming.value);
    let mut claim = fresh.value.add(&ggw);
    let mut rho = Vec::with_capacity(k_log + 1);
    for wire in &proof.phase1_rounds {
        let (next, r) = compressed_deg2_round(b, ch, &claim, wire);
        claim = next;
        rho.push(r);
    }
    // Terminal: ŵu~(ρ)·g_v + γ·gate·eq(p_in^{rb}, ρ)·g_e == claim.
    let ell = 1usize << k_skip;
    let lambda = lagrange_weights_window_trace(b, &fresh.z_skip, 0, ell, 0);
    let lam = small_mle_eval_trace(b, &lambda, &rho[..k_skip]);
    let e = eq_points_trace(b, &fresh.x_inner_rest, &rho[k_skip..k_log]);
    // ŵ(x_b) = α + x_b·(α + 1).
    let one = LinExpr::constant(F128::ONE);
    let wb = fresh
        .alpha
        .add(&mul(b, &rho[k_log], &fresh.alpha.add(&one)));
    let wu = mul(b, &lam, &e);
    let wu = mul(b, &wu, &wb);
    let ein = eq_points_trace(b, p_in_row, &rho);
    let t1 = mul(b, &wu, &proof.g_v);
    let t2 = mul(b, &gg, &ein);
    let t2 = mul(b, &t2, &proof.g_e);
    pin_eq(b, &t1.add(&t2), &claim);

    ch.observe_f128(b, &proof.g_v);
    ch.observe_f128(b, &proof.g_e);
    let delta = ch.sample_f128(b);
    let dg = mul(b, &delta, gate);

    // Phase 2.
    let dgw = mul(b, &dg, &proof.g_e);
    let mut claim = proof.g_v.add(&dgw);
    let mut sigma = Vec::with_capacity(k_log);
    for wire in &proof.phase2_rounds {
        let (next, r) = compressed_deg2_round(b, ch, &claim, wire);
        claim = next;
        sigma.push(r);
    }
    // Terminal: [ṽ(σ) + δ·gate·eq(p_in^c, σ)]·final == claim.
    let zp = small_mle_eval_trace(b, &fresh.z_partial, &sigma[..k_skip]);
    let q = eq_points_trace(b, &fresh.r_inner_rest, &sigma[k_skip..]);
    let v = mul(b, &zp, &q);
    let ec = eq_points_trace(b, p_in_col, &sigma);
    let dec = mul(b, &dg, &ec);
    let weight = v.add(&dec);
    let expected = mul(b, &weight, &proof.final_matrix_eval);
    pin_eq(b, &expected, &claim);
    ch.observe_f128(b, &proof.final_matrix_eval);

    let mut point = rho;
    point.extend(sigma);
    MatrixAccClaimTrace {
        point,
        value: proof.final_matrix_eval.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_matrix_claim_fold_c1_trace(
    b: &mut FieldR1csBuilder,
    channel: &mut impl FsChannelOps,
    k_log: usize,
    k_skip: usize,
    fresh: &C1FreshLincheckClaimTrace,
    incoming: &C1MatrixAccClaimTrace,
    gate: &LinExpr,
    proof: &C1MatrixFoldProofTrace,
) -> C1MatrixAccClaimTrace {
    assert_eq!(fresh.x_inner_rest.len(), k_log - k_skip);
    assert_eq!(fresh.r_inner_rest.len(), k_log - k_skip);
    assert_eq!(fresh.z_partial.len(), 1usize << k_skip);
    assert_eq!(incoming.point.len(), 2 * k_log + 1);

    channel.observe_label(b, b"history-matrix-claim-fold-c1");
    channel.observe_f256(b, &fresh.alpha);
    channel.observe_f256(b, &fresh.z_skip);
    channel.observe_f256_slice(b, &fresh.x_inner_rest);
    channel.observe_f256_slice(b, &fresh.r_inner_rest);
    channel.observe_f256_slice(b, &fresh.z_partial);
    channel.observe_f256(b, &fresh.value);
    channel.observe_f256_slice(b, &incoming.point);
    channel.observe_f256(b, &incoming.value);
    let gate_ext = ExtExpr::from_base(gate.clone());
    channel.observe_f256(b, &gate_ext);
    let gamma = channel.sample_f256(b);
    let gamma_gate = super::mul_ext_base(b, &gamma, gate);
    let (incoming_row, incoming_column) = incoming.point.split_at(k_log + 1);

    let mut claim = fresh.value.add(&mul_ext(b, &gamma_gate, &incoming.value));
    let mut rho = Vec::with_capacity(k_log + 1);
    for wire in &proof.phase1_rounds {
        let (next, challenge) = compressed_deg2_round_c1(b, channel, &claim, wire);
        claim = next;
        rho.push(challenge);
    }

    let count = 1usize << k_skip;
    let lambda = lagrange_weights_window_ext_trace(b, &fresh.z_skip, 0, count, 0);
    let low = evaluate_slice_ext_trace(b, &lambda, &rho[..k_skip]);
    let rest = eq_points_c1_trace(b, &fresh.x_inner_rest, &rho[k_skip..k_log]);
    let stack = fresh
        .alpha
        .add(&mul_ext(b, &rho[k_log], &fresh.alpha.add_const(F256::ONE)));
    let low_rest = mul_ext(b, &low, &rest);
    let fresh_weight = mul_ext(b, &low_rest, &stack);
    let incoming_weight = eq_points_c1_trace(b, incoming_row, &rho);
    let first = mul_ext(b, &fresh_weight, &proof.g_v);
    let second = mul_ext(b, &gamma_gate, &incoming_weight);
    let second = mul_ext(b, &second, &proof.g_e);
    pin_eq_ext(b, &first.add(&second), &claim);

    channel.observe_f256(b, &proof.g_v);
    channel.observe_f256(b, &proof.g_e);
    let delta = channel.sample_f256(b);
    let delta_gate = super::mul_ext_base(b, &delta, gate);

    let mut claim = proof.g_v.add(&mul_ext(b, &delta_gate, &proof.g_e));
    let mut sigma = Vec::with_capacity(k_log);
    for wire in &proof.phase2_rounds {
        let (next, challenge) = compressed_deg2_round_c1(b, channel, &claim, wire);
        claim = next;
        sigma.push(challenge);
    }
    let partial = evaluate_slice_ext_trace(b, &fresh.z_partial, &sigma[..k_skip]);
    let rest = eq_points_c1_trace(b, &fresh.r_inner_rest, &sigma[k_skip..]);
    let fresh_weight = mul_ext(b, &partial, &rest);
    let incoming_weight = eq_points_c1_trace(b, incoming_column, &sigma);
    let incoming_weight = mul_ext(b, &delta_gate, &incoming_weight);
    let expected = mul_ext(
        b,
        &fresh_weight.add(&incoming_weight),
        &proof.final_matrix_eval,
    );
    pin_eq_ext(b, &expected, &claim);
    channel.observe_f256(b, &proof.final_matrix_eval);

    let mut point = rho;
    point.extend(sigma);
    C1MatrixAccClaimTrace {
        point,
        value: proof.final_matrix_eval.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
    use noid_ivc_core::field_r1cs::{FieldR1cs, SparseFieldMatrix};
    use noid_ivc_core::matrix_claim::c1::{
        fresh_claim_value_c1, prove_matrix_claim_fold_c1, stacked_matrix_mle_eval_c1,
        C1FreshLincheckClaim, C1MatrixAccClaim,
    };
    use noid_ivc_core::matrix_claim::{
        fresh_claim_value, prove_matrix_claim_fold, stacked_matrix_mle_eval, FreshLincheckClaim,
        MatrixAccClaim,
    };

    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn f128(&mut self) -> F128 {
            F128 {
                lo: self.next_u64(),
                hi: self.next_u64(),
            }
        }
        fn f256(&mut self) -> F256 {
            F256::new(self.f128(), self.f128())
        }
    }

    fn random_instance(rng: &mut Rng, k_log: usize) -> FieldR1cs {
        let k = 1usize << k_log;
        let mk = |rng: &mut Rng| {
            SparseFieldMatrix::from_rows(
                k,
                (0..k)
                    .map(|_| {
                        (0..3)
                            .map(|_| ((rng.next_u64() as usize % k) as u32, rng.f128()))
                            .collect()
                    })
                    .collect(),
            )
        };
        FieldR1cs {
            m: k_log,
            k_log,
            k_skip: 6,
            useful_rows: k,
            a_0: mk(rng),
            b_0: mk(rng),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        }
    }

    /// Fold twin: lockstep with the native verifier on a true claim pair,
    /// satisfiable trace, wire mutations rejected, and the outgoing claim
    /// true against the matrix (decider agreement).
    #[test]
    fn matrix_fold_twin_lockstep_and_mutations() {
        let k_log = 7;
        let k_skip = 6;
        let mut rng = Rng(0xF01D);
        let r1cs = random_instance(&mut rng, k_log);
        let rest = k_log - k_skip;
        let mut fresh = FreshLincheckClaim {
            alpha: rng.f128(),
            z_skip: rng.f128(),
            x_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            r_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            z_partial: (0..1 << k_skip).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        fresh.value = fresh_claim_value(&r1cs, &fresh);
        let mut incoming = MatrixAccClaim {
            point: (0..2 * k_log + 1).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        incoming.value = stacked_matrix_mle_eval(&r1cs, &incoming);

        let mut ch_native = FsLaneChallenger::new(b"fold-twin-test");
        let (proof, acc_native) =
            prove_matrix_claim_fold(&r1cs, &fresh, &incoming, true, &mut ch_native);

        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"fold-twin-test");
        let alloc = |b: &mut FieldR1csBuilder, v: F128| LinExpr::from_wire(b.alloc_f128(v));
        let fresh_e = FreshLincheckClaimTrace {
            alpha: alloc(&mut b, fresh.alpha),
            z_skip: alloc(&mut b, fresh.z_skip),
            x_inner_rest: fresh
                .x_inner_rest
                .iter()
                .map(|&v| alloc(&mut b, v))
                .collect(),
            r_inner_rest: fresh
                .r_inner_rest
                .iter()
                .map(|&v| alloc(&mut b, v))
                .collect(),
            z_partial: fresh.z_partial.iter().map(|&v| alloc(&mut b, v)).collect(),
            value: alloc(&mut b, fresh.value),
        };
        let incoming_e = MatrixAccClaimTrace::alloc(&mut b, &incoming);
        let gate = LinExpr::constant(F128::ONE);
        let mutation_start = b.num_wires();
        let proof_e = MatrixFoldProofTrace::alloc(&mut b, &proof, k_log);
        let mutation_end = b.num_wires();
        let acc = verify_matrix_claim_fold_trace(
            &mut b,
            &mut ch,
            k_log,
            k_skip,
            &fresh_e,
            &incoming_e,
            &gate,
            &proof_e,
        );
        let rows = b.num_wires();
        eprintln!("[matrix-fold] twin rows @k_log={k_log}: {rows}");

        // Lockstep + outgoing claim agreement.
        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "fold twin transcript diverged");
        for (e, n) in acc.point.iter().zip(acc_native.point.iter()) {
            assert_eq!(e.eval(b.values()), *n);
        }
        assert_eq!(acc.value.eval(b.values()), acc_native.value);

        let (r1cs_t, z) = b.build();
        assert!(r1cs_t.satisfies(&z), "honest fold twin unsatisfiable");

        let survivors = r1cs_t
            .flip_battery(&z)
            .survivors(mutation_start..mutation_end);
        assert!(survivors.is_empty(), "fold twin survivors: {survivors:?}");
    }

    #[test]
    fn c1_matrix_fold_twin_lockstep_and_mutations() {
        let k_log = 7;
        let k_skip = 6;
        let mut rng = Rng(0xC1F01D);
        let relation = random_instance(&mut rng, k_log);
        let rest = k_log - k_skip;
        let mut fresh = C1FreshLincheckClaim {
            alpha: rng.f256(),
            z_skip: rng.f256(),
            x_inner_rest: (0..rest).map(|_| rng.f256()).collect(),
            r_inner_rest: (0..rest).map(|_| rng.f256()).collect(),
            z_partial: (0..1 << k_skip).map(|_| rng.f256()).collect(),
            value: F256::ZERO,
        };
        fresh.value = fresh_claim_value_c1(&relation, &fresh);
        let mut incoming = C1MatrixAccClaim {
            point: (0..2 * k_log + 1).map(|_| rng.f256()).collect(),
            value: F256::ZERO,
        };
        incoming.value = stacked_matrix_mle_eval_c1(&relation, &incoming);

        let mut native = FsLaneChallenger::new_c1(b"fold-twin-c1-test");
        let (proof, native_accumulator) =
            prove_matrix_claim_fold_c1(&relation, &fresh, &incoming, true, &mut native);

        let mut builder = FieldR1csBuilder::new();
        let mut trace = FsChannelTrace::new_c1(&mut builder, b"fold-twin-c1-test");
        let fresh_trace = C1FreshLincheckClaimTrace {
            alpha: alloc_ext(&mut builder, fresh.alpha),
            z_skip: alloc_ext(&mut builder, fresh.z_skip),
            x_inner_rest: fresh
                .x_inner_rest
                .iter()
                .map(|&value| alloc_ext(&mut builder, value))
                .collect(),
            r_inner_rest: fresh
                .r_inner_rest
                .iter()
                .map(|&value| alloc_ext(&mut builder, value))
                .collect(),
            z_partial: fresh
                .z_partial
                .iter()
                .map(|&value| alloc_ext(&mut builder, value))
                .collect(),
            value: alloc_ext(&mut builder, fresh.value),
        };
        let incoming_trace = C1MatrixAccClaimTrace::alloc(&mut builder, &incoming);
        let mutation_start = builder.num_wires();
        let proof_trace = C1MatrixFoldProofTrace::alloc(&mut builder, &proof, k_log);
        let mutation_end = builder.num_wires();
        let accumulator = verify_matrix_claim_fold_c1_trace(
            &mut builder,
            &mut trace,
            k_log,
            k_skip,
            &fresh_trace,
            &incoming_trace,
            &LinExpr::constant(F128::ONE),
            &proof_trace,
        );

        assert_eq!(
            accumulator
                .point
                .iter()
                .map(|value| value.eval(builder.values()))
                .collect::<Vec<_>>(),
            native_accumulator.point,
        );
        assert_eq!(
            accumulator.value.eval(builder.values()),
            native_accumulator.value,
        );
        let native_next = native.sample_f256();
        let trace_next = trace.sample_f256(&mut builder);
        assert_eq!(trace_next.eval(builder.values()), native_next);

        let (trace_relation, witness) = builder.build();
        assert!(trace_relation.satisfies(&witness));
        let survivors = trace_relation
            .flip_battery(&witness)
            .survivors(mutation_start..mutation_end);
        assert!(
            survivors.is_empty(),
            "C1 fold twin survivors: {survivors:?}"
        );
    }
}
