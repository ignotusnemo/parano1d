//! Polynomial commitment scheme for the bit-MLE witness `ẑ` over GF(2).
//!
//! Construction: Binius-style PCS with F_{2^128} packing.
//!
//! - **Commit**: pack the 2^m Boolean witness into 2^(m−7) F_{2^128} elements
//!   (one bit per polynomial-basis coordinate of F_{2^128}), batch RS-encode
//!   via additive NTT, Merkle-commit the codeword.
//! - **Open**: at a QuirkyPoint (z_skip, x_outer) from the zerocheck/lincheck:
//!   1. [`ring_switch::prove`] sends 128 partial-evaluations `s_hat_v` and
//!      produces a BaseFold target `(rs_eq_ind, sumcheck_claim)`.
//!   2. [`basefold::prove`] runs the bivariate sumcheck of
//!      `⟨packed_witness, rs_eq_ind⟩ = sumcheck_claim` over m−7 rounds.
//! - **Verify**: the verifier replays both steps. After ring-switching it
//!   reconstructs `rs_eq_ind` locally and checks the sumcheck's final value,
//!   then walks the multi-arity FRI codeword folds — verifying per-query
//!   Merkle paths against the T₁ (initial) and T₂ (post-row-batch) roots and
//!   the per-epoch FRI commits, and matching the final folded value against
//!   a plaintext final codeword. See [`basefold::verify`] for the full chain.
//!
//! See [DP24](https://eprint.iacr.org/2024/504) (ring-switching) and the
//! [BaseFold paper](https://link.springer.com/chapter/10.1007/978-3-031-68403-6_5).

pub mod basefold;
pub mod commit;
pub mod ligerito;
pub mod pack;
pub mod ring_switch;
pub mod tensor_algebra;

pub use basefold::{
    BASEFOLD_RATE_QUARTER_C1_QUERIES, BASEFOLD_UDR_TARGET_BITS, BaseFoldProof,
    BaseFoldUdrConfigError, BaseFoldUdrConfiguration, C1BaseFoldProof, C1QueryOpening,
    C1RoundMessage, DEFAULT_FRI_QUERIES, PLAINTEXT_TAIL_MAX_F128, QUERY_GRIND_BITS,
    RoundCommitment, RoundMessage, checked_fri_configuration, default_fri_queries,
    fri_commit_layout, sample_query_positions,
};
pub use commit::{
    Commitment, LOG_FRI_ARITY, PcsParams, PcsProfile, ProverData, commit, commit_into,
    compute_fri_arities, prefault_codeword_during,
};
pub use pack::{LOG_PACKING, pack_witness, unpack_witness};
pub use ring_switch::{RingSwitchProof, SparseEqTensor};

use crate::challenger::Challenger;
use crate::field::{F128, F256};
use crate::zerocheck::PaddingSpec;
use serde::{Deserialize, Serialize};

/// Composite opening proof: ring-switching message + BaseFold proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeningProof {
    pub ring_switch: RingSwitchProof,
    pub basefold: BaseFoldProof,
}

/// Batched opening proof with the **Ligerito** PCS backend instead of BaseFold.
/// Same ring-switching frontend; the combined `b_combined` + target_combined
/// feed [`ligerito::recursive_prover_with_basis`] for a smaller proof at the
/// cost of ~1.4× prover time (see ligerito module docs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchOpeningProofLigerito {
    pub ring_switches: Vec<RingSwitchProof>,
    pub ligerito: ligerito::LigeritoProof,
}

/// Backend-agnostic batched opening proof, carried inside [`crate::proof::R1csProof`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchOpening {
    BaseFold(BatchOpeningProof),
    Ligerito(BatchOpeningProofLigerito),
}

/// Batched opening proof: one ring-switching message per opening point,
/// plus ONE shared BaseFold proof. The BaseFold runs on a random linear
/// combination of the per-point `rs_eq_ind` weights, so a single
/// sumcheck + FRI suffices to prove all opening claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchOpeningProof {
    pub ring_switches: Vec<RingSwitchProof>,
    pub basefold: BaseFoldProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    ProfileMismatch,
    RingSwitch(ring_switch::VerifyError),
    BaseFold(basefold::VerifyError),
    /// BaseFold's `final_b` doesn't match the transparent multilinear's
    /// evaluation at the sampled challenges. Indicates the prover's BaseFold
    /// final value is inconsistent with `rs_eq_ind`.
    FinalBMismatch,
}

/// `eq_ind` representation for a packed-direct claim. The contributed value at
/// scattered index `j` is the tensor entry — for the dense variant the index
/// is the array offset; for the sparse variant it's reconstructed via
/// [`SparseEqTensor::scatter_idx`].
#[derive(Clone, Debug)]
pub enum DirectEqInd {
    /// Fully-materialized `eq_ind(point)` of length `2^L`.
    Dense(Vec<F128>),
    /// Sparse representation — non-zero entries at scattered indices.
    /// Built from a claim point with one or more exactly-zero coords via
    /// [`ring_switch::build_eq_sparse`].
    Sparse(SparseEqTensor),
}

/// A packed-MLE evaluation claim: `ẑ_packed(point) = value`. Unlike a
/// ring-switched claim, this is opened directly via BaseFold without going
/// through the bit-MLE ↔ packed-MLE bridge (no `s_hat_v`, no φ_8 weighting).
///
/// Use case: protocols whose sumcheck output is naturally a packed-MLE
/// evaluation (e.g. the chain shift sumcheck operating on packed columns
/// instead of bit-folded scalars). Skips the ring-switch step for this claim,
/// saving the `fold_1b_rows` + per-opening-tail work at the prover and the
/// ring-switch verify + φ_8 reconstruction at the verifier.
///
/// The basefold combine step adds `γ_k · eq_ind(point)` to `b_combined` and
/// `γ_k · value` to the target; the verifier's `final_b` check contributes
/// `γ_k · eq_eval(point, basefold_challenges)`.
#[derive(Clone, Debug)]
pub struct PackedDirectClaim {
    /// Multilinear point of length `L = m − 7`.
    pub point: Vec<F128>,
    /// Claimed `ẑ_packed(point)` value.
    pub value: F128,
    /// `eq_ind(point)` in dense or sparse form. Caller responsibility to
    /// match the claim's `point` — the contribution to `b_combined` is read
    /// directly from this tensor.
    pub eq_ind: DirectEqInd,
}

/// A **quirky-point** evaluation claim on the packed MLE — the FieldR1cs
/// opening. The committed vector is read as `2^L` F128 *elements*
/// (`L = m − LOG_PACKING`) and the claim point is a zerocheck/lincheck
/// QuirkyPoint over those element variables: `z_skip` binds the low `k_skip`
/// vars via the φ_8 Lagrange basis, `x_rest` (length `L − k_skip`) binds the
/// remaining vars multilinearly.
///
/// Like [`PackedDirectClaim`] this skips ring-switching entirely (there is no
/// bit-MLE ↔ packed-MLE bridge to cross — the witness IS the element vector);
/// unlike it, the eq weighting on the skip block is Lagrange, not multilinear,
/// so it gets its own combine/final_b path
/// ([`open_batch_quirky_direct`] / [`verify_opening_batch_quirky_direct`]).
#[derive(Clone, Debug)]
pub struct QuirkyDirectClaim {
    pub z_skip: F128,
    pub k_skip: usize,
    /// Multilinear coords for vars `k_skip..L`, LSB-first.
    pub x_rest: Vec<F128>,
    /// Claimed evaluation.
    pub value: F128,
}

/// Verifier-side borrow of a [`QuirkyDirectClaim`].
#[derive(Clone, Copy, Debug)]
pub struct QuirkyDirectClaimRef<'a> {
    pub z_skip: F128,
    pub k_skip: usize,
    pub x_rest: &'a [F128],
    pub value: F128,
}

/// C1 quirky opening claim. The committed vector remains F128-valued, while
/// the point and claimed evaluation live in the extension challenge field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C1QuirkyDirectClaim {
    pub z_skip: F256,
    pub k_skip: usize,
    pub x_rest: Vec<F256>,
    pub value: F256,
}

#[derive(Clone, Copy, Debug)]
pub struct C1QuirkyDirectClaimRef<'a> {
    pub z_skip: F256,
    pub k_skip: usize,
    pub x_rest: &'a [F256],
    pub value: F256,
}

/// Batched open over quirky-direct claims only (the FieldR1cs path): one
/// BaseFold on the γ-combined quirky eq tensors. No ring-switch messages —
/// the proof is a bare [`BaseFoldProof`].
///
/// Transcript: label → per-claim full descriptor
/// `(z_skip, k_skip, x_rest, value)` → γ per claim → BaseFold.
///
/// Most claim points are already transcript-derived by their producing
/// sub-protocol.  Absorbing the descriptor again is deliberate: it binds the
/// batch order and also permits post-commit auxiliary protocols to append
/// claims without relying on an implicit "the point was observed somewhere
/// earlier" precondition.
/// Low index bits covered by each claim's fused lo table in
/// [`open_batch_quirky_direct`]. Must be at least the largest production
/// `k_skip` (6) and small enough that one lo block and the per-claim tables
/// stay cache-resident: 2^12 · 16 B = 64 KiB per table.
const B_COMBINED_SPLIT_LOG: usize = 12;

pub fn open_batch_quirky_direct<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    claims: &[QuirkyDirectClaim],
    challenger: &mut Ch,
) -> BaseFoldProof {
    use rayon::prelude::*;

    assert!(!claims.is_empty(), "need at least one claim");
    let l = packed_witness.len();
    debug_assert!(l.is_power_of_two());
    let l_log = l.trailing_zeros() as usize;
    for c in claims {
        assert_eq!(
            c.x_rest.len() + c.k_skip,
            l_log,
            "claim point/witness L mismatch"
        );
    }

    challenger.observe_label(b"history-pcs-open-field-v1");
    for c in claims {
        challenger.observe_label(b"history-pcs-quirky-direct-v1");
        challenger.observe_f128(c.z_skip);
        challenger.observe_f128(F128::new(c.k_skip as u64, 0));
        challenger.observe_f128_slice(&c.x_rest);
        challenger.observe_f128(c.value);
    }
    let gammas: Vec<F128> = (0..claims.len())
        .map(|_| challenger.sample_f128())
        .collect();

    let mut target_combined = F128::ZERO;
    for (c, g) in claims.iter().zip(gammas.iter()) {
        target_combined += *g * c.value;
    }

    let trace = std::env::var("PCS_TRACE").is_ok();
    let mut t = std::time::Instant::now();
    let lap = move |label: &str, t: &mut std::time::Instant| {
        if trace {
            eprintln!(
                "  [open_batch_quirky] {label}: {:.2} ms",
                t.elapsed().as_secs_f64() * 1e3
            );
        }
        *t = std::time::Instant::now();
    };
    if trace {
        eprintln!("  [open_batch_quirky] claims: {}", claims.len());
    }

    // b_combined[i] = Σ_k γ_k · L_{i_skip}(z_skip_k) · eq(x_rest_k, i_rest).
    // γ_k is baked into the (tiny) Lagrange table. Claims may carry
    // DIFFERENT k_skip (quirky sub-protocol claims at K_SKIP next to plain
    // k_skip = 0 point claims).
    //
    // The eq tensor is split per claim into one lo table over the low
    // `B_COMBINED_SPLIT_LOG` index bits (Lagrange block ⊗ low eq coords,
    // γ folded in) and one hi table over the remaining coords, and every
    // claim is accumulated in a single fused pass per lo-sized block. The
    // earlier per-claim form materialized a full 2^l eq table and one full
    // read-modify-write pass per claim — with the ~10² deferred sidecar
    // claims of a production Block that was tens of GiB of memory traffic;
    // the fused pass touches `b_combined` once while every per-claim table
    // stays cache-resident. Addition is XOR, so the regrouped accumulation
    // is bit-identical.
    let split = B_COMBINED_SPLIT_LOG.min(l_log);
    let lo_len = 1usize << split;
    let mut lo_tables: Vec<Vec<F128>> = Vec::with_capacity(claims.len());
    let mut hi_tables: Vec<Vec<F128>> = Vec::with_capacity(claims.len());
    for (c, g) in claims.iter().zip(gammas.iter()) {
        assert!(
            c.k_skip <= split,
            "quirky claim k_skip {} exceeds the b_combined split {split}",
            c.k_skip
        );
        let mut weights = crate::zerocheck::multilinear::lagrange_weights_naive(c.k_skip, c.z_skip);
        for w in weights.iter_mut() {
            *w *= *g;
        }
        let eq_lo = crate::lincheck::build_eq_table(&c.x_rest[..split - c.k_skip]);
        let mut lo = Vec::with_capacity(lo_len);
        for &e_lo in &eq_lo {
            for w in &weights {
                lo.push(e_lo * *w);
            }
        }
        debug_assert_eq!(lo.len(), lo_len);
        lo_tables.push(lo);
        hi_tables.push(crate::lincheck::build_eq_table(
            &c.x_rest[split - c.k_skip..],
        ));
    }
    let mut b_combined: Vec<F128> = crate::scratch::take_f128(l);
    // BaseFold's first sumcheck message is a reduction over the same
    // `packed_witness`/`b_combined` pairs that this pass has hot in cache.
    // Prime it here instead of making BaseFold stream both 2^m vectors once
    // more.  `lo_len` is a power of two; every non-trivial domain therefore
    // keeps pairs inside one output block.  The degenerate length-one domain
    // falls back to BaseFold's own prime path below.
    let fuse_round0_prime = lo_len >= 2;
    let round0_prime = b_combined
        .par_chunks_mut(lo_len)
        .enumerate()
        .map(|(hi, out_block)| {
            out_block.fill(F128::ZERO);
            for (lo_table, hi_table) in lo_tables.iter().zip(&hi_tables) {
                let scale = hi_table[hi];
                if scale == F128::ZERO {
                    continue;
                }
                for (slot, lo_value) in out_block.iter_mut().zip(lo_table) {
                    *slot += scale * *lo_value;
                }
            }
            if !fuse_round0_prime {
                return (F128::ZERO, F128::ZERO);
            }
            let base = hi * lo_len;
            let mut u0 = F128::ZERO;
            let mut u2 = F128::ZERO;
            for (pair, values) in out_block.chunks_exact(2).enumerate() {
                let a0 = packed_witness[base + 2 * pair];
                let a1 = packed_witness[base + 2 * pair + 1];
                let b0 = values[0];
                let b1 = values[1];
                u0 += a0 * b0;
                u2 += (a0 + a1) * (b0 + b1);
            }
            (u0, u2)
        })
        .reduce(
            || (F128::ZERO, F128::ZERO),
            |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2),
        );
    lap("b_combined build", &mut t);

    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    lap("ntt tables", &mut t);
    let proof = basefold::prove_with_precomputed_round0_prime_with_node_hash(
        packed_witness,
        b_combined,
        target_combined,
        &prover_data.codeword,
        &prover_data.merkle_tree,
        &ntt,
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        default_fri_queries(commitment.params.log_dim(), commitment.params.log_inv_rate),
        fuse_round0_prime.then_some(round0_prime),
        challenger,
        commitment.params.node_hash_version(),
    );
    lap("basefold", &mut t);
    proof
}

/// Verify a [`open_batch_quirky_direct`] proof. Mirror transcript; the
/// `final_b` contribution of each claim factorizes as
/// `(Σ_{i ∈ {0,1}^k_skip} eq(challenges[..k_skip], i) · L_i(z_skip)) ·
/// eq(x_rest, challenges[k_skip..])` — the MLE of the Lagrange-weight table
/// over the skip bits, times the standard multilinear factor.
pub fn verify_opening_batch_quirky_direct<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[QuirkyDirectClaimRef<'_>],
    proof: &BaseFoldProof,
    challenger: &mut Ch,
) -> Result<(), VerifyError> {
    use crate::zerocheck::multilinear::{eq_eval, lagrange_weights_naive};

    assert!(!claims.is_empty(), "need at least one claim");
    let l_log = commitment.params.m - LOG_PACKING;
    for c in claims {
        assert_eq!(
            c.x_rest.len() + c.k_skip,
            l_log,
            "claim point/witness L mismatch"
        );
    }

    challenger.observe_label(b"history-pcs-open-field-v1");
    for c in claims {
        challenger.observe_label(b"history-pcs-quirky-direct-v1");
        challenger.observe_f128(c.z_skip);
        challenger.observe_f128(F128::new(c.k_skip as u64, 0));
        challenger.observe_f128_slice(c.x_rest);
        challenger.observe_f128(c.value);
    }
    let gammas: Vec<F128> = (0..claims.len())
        .map(|_| challenger.sample_f128())
        .collect();

    let mut target_combined = F128::ZERO;
    for (c, g) in claims.iter().zip(gammas.iter()) {
        target_combined += *g * c.value;
    }

    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    let challenges = basefold::verify_with_node_hash(
        target_combined,
        proof,
        &commitment.root,
        &ntt,
        l_log,
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        challenger,
        commitment.params.node_hash_version(),
    )
    .map_err(VerifyError::BaseFold)?;
    debug_assert_eq!(challenges.len(), l_log);

    let mut expected_final_b = F128::ZERO;
    for (c, g) in claims.iter().zip(gammas.iter()) {
        let weights = lagrange_weights_naive(c.k_skip, c.z_skip);
        let eq_skip = crate::lincheck::build_eq_table(&challenges[..c.k_skip]);
        let mut skip_factor = F128::ZERO;
        for (w, e) in weights.iter().zip(eq_skip.iter()) {
            skip_factor += *w * *e;
        }
        expected_final_b += *g * skip_factor * eq_eval(c.x_rest, &challenges[c.k_skip..]);
    }
    if expected_final_b != proof.final_b {
        return Err(VerifyError::FinalBMismatch);
    }
    Ok(())
}

/// C1 batched quirky-direct opening. Claim descriptors and batching scalars
/// are wide, but T1 remains the existing F128 codeword commitment. The fused
/// tensor build also primes C1 BaseFold's first sumcheck message so the wide
/// witness/tensor pair is streamed only once before folding.
pub fn open_batch_quirky_direct_c1<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    claims: &[C1QuirkyDirectClaim],
    challenger: &mut Ch,
) -> C1BaseFoldProof {
    open_batch_quirky_direct_c1_slices(
        packed_witness,
        &prover_data.codeword,
        &prover_data.merkle_tree,
        commitment,
        claims,
        challenger,
    )
}

/// The same opening protocol over immutable resident or disk-backed slices.
/// This changes storage ownership, not the transcript or verifier.
pub(crate) fn open_batch_quirky_direct_c1_slices<Ch: Challenger>(
    packed_witness: &[F128],
    codeword: &[F128],
    merkle_tree: &[crate::merkle::Hash],
    commitment: &Commitment,
    claims: &[C1QuirkyDirectClaim],
    challenger: &mut Ch,
) -> C1BaseFoldProof {
    use rayon::prelude::*;

    assert!(!claims.is_empty(), "need at least one C1 claim");
    let length = packed_witness.len();
    debug_assert!(length.is_power_of_two());
    let log_length = length.trailing_zeros() as usize;
    for claim in claims {
        assert_eq!(claim.x_rest.len() + claim.k_skip, log_length);
    }

    challenger.observe_label(b"history-pcs-open-field-c1");
    for claim in claims {
        challenger.observe_label(b"history-pcs-quirky-direct-c1");
        challenger.observe_f256(claim.z_skip);
        challenger.observe_f256(F256::from_base(F128::new(claim.k_skip as u64, 0)));
        challenger.observe_f256_slice(&claim.x_rest);
        challenger.observe_f256(claim.value);
    }
    let gammas = (0..claims.len())
        .map(|_| challenger.sample_f256())
        .collect::<Vec<_>>();
    let target = claims
        .iter()
        .zip(&gammas)
        .fold(F256::ZERO, |sum, (claim, &gamma)| sum + gamma * claim.value);

    let split = B_COMBINED_SPLIT_LOG.min(log_length);
    let low_length = 1usize << split;
    let mut low_tables = Vec::with_capacity(claims.len());
    let mut high_tables = Vec::with_capacity(claims.len());
    for (claim, &gamma) in claims.iter().zip(&gammas) {
        assert!(claim.k_skip <= split);
        let mut skip = crate::zerocheck::field_c1::lagrange_weights(claim.k_skip, claim.z_skip, 0);
        skip.iter_mut().for_each(|weight| *weight *= gamma);
        let eq_low =
            crate::zerocheck::field_c1::build_eq_table(&claim.x_rest[..split - claim.k_skip]);
        let mut low = Vec::with_capacity(low_length);
        for &eq in &eq_low {
            for &weight in &skip {
                low.push(eq * weight);
            }
        }
        debug_assert_eq!(low.len(), low_length);
        low_tables.push(low);
        high_tables.push(crate::zerocheck::field_c1::build_eq_table(
            &claim.x_rest[split - claim.k_skip..],
        ));
    }

    // Every output block is explicitly zeroed before accumulation; the
    // uninitialized allocation avoids a second serial full-vector write.
    let mut combined: Vec<F256> = crate::alloc_uninit_vec(length);
    let fuse_round_zero = low_length >= 2;
    let round_zero_prime = combined
        .par_chunks_mut(low_length)
        .enumerate()
        .map(|(high, output)| {
            output.fill(F256::ZERO);
            for (low, high_table) in low_tables.iter().zip(&high_tables) {
                let scale = high_table[high];
                if scale.is_zero() {
                    continue;
                }
                for (slot, &low_value) in output.iter_mut().zip(low) {
                    *slot += scale * low_value;
                }
            }
            if !fuse_round_zero {
                return (F256::ZERO, F256::ZERO);
            }
            let base = high * low_length;
            let mut u_0 = F256::ZERO;
            let mut u_2 = F256::ZERO;
            for (pair, values) in output.chunks_exact(2).enumerate() {
                let a_0 = packed_witness[base + 2 * pair];
                let a_1 = packed_witness[base + 2 * pair + 1];
                u_0 += values[0].scale_base(a_0);
                u_2 += (values[0] + values[1]).scale_base(a_0 + a_1);
            }
            (u_0, u_2)
        })
        .reduce(
            || (F256::ZERO, F256::ZERO),
            |left, right| (left.0 + right.0, left.1 + right.1),
        );

    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    basefold::prove_c1_with_precomputed_round0_prime_with_node_hash(
        packed_witness,
        combined,
        target,
        codeword,
        merkle_tree,
        &ntt,
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        default_fri_queries(commitment.params.log_dim(), commitment.params.log_inv_rate),
        fuse_round_zero.then_some(round_zero_prime),
        challenger,
        commitment.params.node_hash_version(),
    )
}

/// Verify the C1 quirky-direct batch and its wide transparent tensor value.
pub fn verify_opening_batch_quirky_direct_c1<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[C1QuirkyDirectClaimRef<'_>],
    proof: &C1BaseFoldProof,
    challenger: &mut Ch,
) -> Result<(), VerifyError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    assert!(!claims.is_empty(), "need at least one C1 claim");
    let log_length = commitment.params.m - LOG_PACKING;
    for claim in claims {
        assert_eq!(claim.x_rest.len() + claim.k_skip, log_length);
    }

    challenger.observe_label(b"history-pcs-open-field-c1");
    for claim in claims {
        challenger.observe_label(b"history-pcs-quirky-direct-c1");
        challenger.observe_f256(claim.z_skip);
        challenger.observe_f256(F256::from_base(F128::new(claim.k_skip as u64, 0)));
        challenger.observe_f256_slice(claim.x_rest);
        challenger.observe_f256(claim.value);
    }
    let gammas = (0..claims.len())
        .map(|_| challenger.sample_f256())
        .collect::<Vec<_>>();
    let target = claims
        .iter()
        .zip(&gammas)
        .fold(F256::ZERO, |sum, (claim, &gamma)| sum + gamma * claim.value);
    let transcript_micros = total_started.elapsed().as_micros();

    let basefold_started = std::time::Instant::now();
    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    let challenges = basefold::verify_c1_with_node_hash(
        target,
        proof,
        &commitment.root,
        &ntt,
        log_length,
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        challenger,
        commitment.params.node_hash_version(),
    )
    .map_err(VerifyError::BaseFold)?;
    let basefold_micros = basefold_started.elapsed().as_micros();

    let final_b_started = std::time::Instant::now();
    let eq_eval = |left: &[F256], right: &[F256]| {
        assert_eq!(left.len(), right.len());
        left.iter()
            .zip(right)
            .fold(F256::ONE, |product, (&left, &right)| {
                product * (F256::ONE + left + right)
            })
    };
    let mut expected_final_b = F256::ZERO;
    for (claim, &gamma) in claims.iter().zip(&gammas) {
        let skip = crate::zerocheck::field_c1::lagrange_weights(claim.k_skip, claim.z_skip, 0);
        let eq_skip = crate::zerocheck::field_c1::build_eq_table(&challenges[..claim.k_skip]);
        let skip_factor = skip
            .iter()
            .zip(&eq_skip)
            .fold(F256::ZERO, |sum, (&weight, &eq)| sum + weight * eq);
        expected_final_b +=
            gamma * skip_factor * eq_eval(claim.x_rest, &challenges[claim.k_skip..]);
    }
    if expected_final_b != proof.final_b {
        return Err(VerifyError::FinalBMismatch);
    }
    if timing {
        eprintln!(
            "[pcs-c1 verify] transcript_us={transcript_micros} basefold_us={basefold_micros} final_b_us={} total_us={}",
            final_b_started.elapsed().as_micros(),
            total_started.elapsed().as_micros(),
        );
    }
    Ok(())
}

/// Open the committed witness at a zerocheck-style point `(z_skip, x_outer)`.
///
/// `packed_witness` is the same F_{2^128}-packed witness that was passed to
/// [`commit`] — caller must retain its own copy (it is NOT stored in
/// `ProverData`). `prover_data` is the output of [`commit`]. `x_outer` is the
/// multilinear portion of the QuirkyPoint with length `m − 6`.
pub fn open<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    x_outer: &[F128],
    challenger: &mut Ch,
) -> OpeningProof {
    challenger.observe_label(b"history-pcs-open-v0");
    let (rs_proof, rs_output) = ring_switch::prove(packed_witness, x_outer, challenger);
    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    let bf_proof = basefold::prove_with_node_hash(
        packed_witness,
        rs_output.rs_eq_ind,
        rs_output.sumcheck_claim,
        &prover_data.codeword,
        &prover_data.merkle_tree,
        &ntt,
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        default_fri_queries(commitment.params.log_dim(), commitment.params.log_inv_rate),
        challenger,
        commitment.params.node_hash_version(),
    );
    OpeningProof {
        ring_switch: rs_proof,
        basefold: bf_proof,
    }
}

/// Batched open at multiple points (`x_outers[0..n]`) against the same
/// commitment. Runs ring-switching once per point, then ONE BaseFold prove
/// on the random-linear-combination of the per-point `rs_eq_ind` weights.
///
/// At m=29 this roughly halves total open cost vs calling `open` twice.
pub fn open_batch<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    x_outers: &[&[F128]],
    challenger: &mut Ch,
) -> BatchOpeningProof {
    open_batch_padded(
        packed_witness,
        prover_data,
        commitment,
        x_outers,
        &PaddingSpec::dense(commitment.params.m),
        challenger,
    )
}

/// Padding-aware variant of [`open_batch`]. Threads `padding` into
/// ring-switching's `fold_1b_rows` so per-block padding chunks are skipped.
/// Byte-identical to the dense path on honestly zero-padded witnesses.
pub fn open_batch_padded<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    x_outers: &[&[F128]],
    padding: &PaddingSpec,
    challenger: &mut Ch,
) -> BatchOpeningProof {
    open_batch_mixed(
        packed_witness,
        prover_data,
        commitment,
        x_outers,
        &[],
        padding,
        challenger,
    )
}

/// Variant of [`open_batch_padded`] that accepts a per-claim optional
/// precomputed `s_hat_v`. See [`open_batch_mixed_with_precomputed_s_hat_v`].
#[allow(clippy::too_many_arguments)]
pub fn open_batch_padded_with_precomputed_s_hat_v<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    x_outers: &[&[F128]],
    precomputed_s_hat_v: &[Option<&[F128]>],
    padding: &PaddingSpec,
    challenger: &mut Ch,
) -> BatchOpeningProof {
    open_batch_mixed_with_precomputed_s_hat_v(
        packed_witness,
        prover_data,
        commitment,
        x_outers,
        precomputed_s_hat_v,
        &[],
        padding,
        challenger,
    )
}

/// Mixed-claim batched open: supports both **ring-switched** claims (the
/// classical path — bit-MLE openings reduced via `ring_switch::prove_batched`)
/// and **packed-direct** claims (packed-MLE openings that skip ring-switch and
/// contribute directly to BaseFold).
///
/// Packed-direct claims save the chain claim's ring-switch work (no `s_hat_v`,
/// no per-opening-tail `fold_b128_elems_sparse_pairs`) when the producer of the
/// claim is already at the packed level (e.g. a column-level lincheck whose
/// sumcheck output is a packed-MLE evaluation).
///
/// Transcript order: label → ring-switched claims (each: label + `s_hat_v_i` +
/// sample `r_dprime_i`) → packed-direct claims (each: `value_k` observed) →
/// sample γ's (one per total claim, ring-switched first) → BaseFold.
#[allow(clippy::too_many_arguments)]
pub fn open_batch_mixed<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    x_outers: &[&[F128]],
    packed_direct: &[PackedDirectClaim],
    padding: &PaddingSpec,
    challenger: &mut Ch,
) -> BatchOpeningProof {
    open_batch_mixed_with_precomputed_s_hat_v(
        packed_witness,
        prover_data,
        commitment,
        x_outers,
        &[],
        packed_direct,
        padding,
        challenger,
    )
}

/// Variant of [`open_batch_mixed`] that accepts a per-ring-switched-claim
/// optional precomputed `s_hat_v`. When `Some(v)` is supplied for claim `i`,
/// ring-switch skips that claim's `fold_1b_rows` and uses `v` directly. Used
/// by the prover to reuse lincheck's pre-sumcheck `z_vec` as the source for
/// the AB-claim's `s_hat_v` — see [`ring_switch::s_hat_v_from_z_vec`].
///
/// `precomputed_s_hat_v` must be `&[]` or have length `x_outers.len()`.
#[allow(clippy::too_many_arguments)]
pub fn open_batch_mixed_with_precomputed_s_hat_v<Ch: Challenger>(
    packed_witness: &[F128],
    prover_data: &ProverData,
    commitment: &Commitment,
    x_outers: &[&[F128]],
    precomputed_s_hat_v: &[Option<&[F128]>],
    packed_direct: &[PackedDirectClaim],
    padding: &PaddingSpec,
    challenger: &mut Ch,
) -> BatchOpeningProof {
    let trace = std::env::var("PCS_TRACE").is_ok();
    let t_total = std::time::Instant::now();

    let combined = compute_combined_basis_and_target(
        packed_witness,
        x_outers,
        precomputed_s_hat_v,
        packed_direct,
        padding,
        challenger,
        trace,
    );

    // BaseFold + FRI on the combined claim.
    let t = std::time::Instant::now();
    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    if trace {
        eprintln!(
            "  [open_batch] AdditiveNttF128::standard: {:6.2} ms",
            t.elapsed().as_secs_f64() * 1e3
        );
    }
    let t = std::time::Instant::now();
    let bf_proof = basefold::prove_with_precomputed_round0_prime_with_node_hash(
        packed_witness,
        combined.b_combined,
        combined.target_combined,
        &prover_data.codeword,
        &prover_data.merkle_tree,
        &ntt,
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        default_fri_queries(commitment.params.log_dim(), commitment.params.log_inv_rate),
        Some(combined.round0_prime),
        challenger,
        commitment.params.node_hash_version(),
    );
    if trace {
        eprintln!(
            "  [open_batch] basefold::prove: {:6.2} ms",
            t.elapsed().as_secs_f64() * 1e3
        );
        eprintln!(
            "  [open_batch] TOTAL: {:6.2} ms",
            t_total.elapsed().as_secs_f64() * 1e3
        );
    }

    BatchOpeningProof {
        ring_switches: combined.ring_switches,
        basefold: bf_proof,
    }
}

/// Ligerito-backend counterpart to [`open_batch_mixed_with_precomputed_s_hat_v`].
/// Shares the ring_switch + b_combined computation, then routes to
/// [`ligerito::recursive_prover_with_basis`] using the existing `prover_data`'s
/// codeword + tree as Ligerito's L0 commit (no L0 re-commit).
///
/// `lig_config.initial_k` must equal `commitment.params.log_batch_size` so that
/// `prover_data`'s codeword/tree shape matches what Ligerito expects for L0.
#[allow(clippy::too_many_arguments)]
pub fn open_batch_mixed_ligerito_with_precomputed_s_hat_v<Ch: Challenger>(
    packed_witness: Vec<F128>,
    prover_data: &ProverData,
    commitment: &Commitment,
    x_outers: &[&[F128]],
    precomputed_s_hat_v: &[Option<&[F128]>],
    packed_direct: &[PackedDirectClaim],
    padding: &PaddingSpec,
    lig_config: &ligerito::ProverConfig,
    challenger: &mut Ch,
) -> BatchOpeningProofLigerito {
    let trace = std::env::var("PCS_TRACE").is_ok();
    let t_total = std::time::Instant::now();

    assert_eq!(
        lig_config.initial_k, commitment.params.log_batch_size,
        "ligerito initial_k ({}) must match PcsParams.log_batch_size ({}) for L0 reuse",
        lig_config.initial_k, commitment.params.log_batch_size,
    );
    assert_eq!(
        lig_config.log_inv_rates[0], commitment.params.log_inv_rate,
        "ligerito log_inv_rates[0] ({}) must match PcsParams.log_inv_rate ({}) for L0 reuse",
        lig_config.log_inv_rates[0], commitment.params.log_inv_rate,
    );

    let combined = compute_combined_basis_and_target(
        &packed_witness,
        x_outers,
        precomputed_s_hat_v,
        packed_direct,
        padding,
        challenger,
        trace,
    );

    let t = std::time::Instant::now();
    let ligerito_proof = ligerito::recursive_prover_with_basis_precomputed_round0(
        lig_config,
        packed_witness,
        combined.b_combined,
        combined.target_combined,
        &prover_data.codeword,
        &prover_data.merkle_tree,
        combined.round0_prime,
        challenger,
    );
    if trace {
        eprintln!(
            "  [open_batch] ligerito::recursive_prover_with_basis: {:6.2} ms",
            t.elapsed().as_secs_f64() * 1e3
        );
        eprintln!(
            "  [open_batch] TOTAL: {:6.2} ms",
            t_total.elapsed().as_secs_f64() * 1e3
        );
    }

    BatchOpeningProofLigerito {
        ring_switches: combined.ring_switches,
        ligerito: ligerito_proof,
    }
}

/// What ring_switch + claim-combination produces, fed to either BaseFold or Ligerito.
struct CombinedClaim {
    ring_switches: Vec<RingSwitchProof>,
    b_combined: Vec<F128>,
    target_combined: F128,
    /// BaseFold's round-0 sumcheck `(u_0, u_2)` prime. Ligerito ignores it.
    round0_prime: (F128, F128),
}

/// Shared by both backends: runs ring_switch over RS claims, observes packed-
/// direct claim values + samples their gammas, then builds `b_combined` (the
/// γ-weighted linear combination of all `rs_eq_ind`s and `eq_ind`s) and
/// `target_combined`. Also computes the BaseFold round-0 prime as a side
/// effect (cheap since it shares the b_combined pass).
#[allow(clippy::too_many_arguments)]
fn compute_combined_basis_and_target<Ch: Challenger>(
    packed_witness: &[F128],
    x_outers: &[&[F128]],
    precomputed_s_hat_v: &[Option<&[F128]>],
    packed_direct: &[PackedDirectClaim],
    padding: &PaddingSpec,
    challenger: &mut Ch,
    trace: bool,
) -> CombinedClaim {
    let n_rs = x_outers.len();
    let n_pd = packed_direct.len();
    assert!(n_rs + n_pd > 0, "open_batch_mixed: need at least one claim");
    assert!(
        precomputed_s_hat_v.is_empty() || precomputed_s_hat_v.len() == n_rs,
        "precomputed_s_hat_v: must be empty or length {n_rs}, got {}",
        precomputed_s_hat_v.len(),
    );

    challenger.observe_label(b"history-pcs-open-batch-v0");

    // 1. Ring-switching for all x_outers.
    let t = std::time::Instant::now();
    let (rs_results, gammas_rs): (
        Vec<(RingSwitchProof, ring_switch::RingSwitchBatchOutput)>,
        Vec<F128>,
    ) = if n_rs > 0 {
        ring_switch::prove_batched_padded_with_precomputed(
            packed_witness,
            x_outers,
            precomputed_s_hat_v,
            padding,
            challenger,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    if trace {
        eprintln!(
            "  [open_batch] ring_switch::prove_batched ×{}: {:6.2} ms",
            n_rs,
            t.elapsed().as_secs_f64() * 1e3
        );
    }

    // 2. Observe packed-direct claim values + sample γ_pd.
    for pd in packed_direct {
        challenger.observe_label(b"history-pcs-packed-direct-v0");
        challenger.observe_f128(pd.value);
    }
    let gammas_pd: Vec<F128> = (0..n_pd).map(|_| challenger.sample_f128()).collect();

    let t = std::time::Instant::now();
    use rayon::prelude::*;

    let l = if let Some((_, out)) = rs_results.first() {
        out.rs_eq_ind.len()
    } else {
        1usize << packed_direct[0].point.len()
    };
    debug_assert!(rs_results.iter().all(|(_, o)| o.rs_eq_ind.len() == l));
    debug_assert!(
        packed_direct.iter().all(|pd| 1usize << pd.point.len() == l),
        "all packed-direct claims must share L (= packed witness length)"
    );

    let mut target_combined = F128::ZERO;
    for ((_, output), g) in rs_results.iter().zip(gammas_rs.iter()) {
        target_combined += *g * output.sumcheck_claim;
    }
    for (pd, g) in packed_direct.iter().zip(gammas_pd.iter()) {
        target_combined += *g * pd.value;
    }

    let rs_baked: Vec<&[F128]> = rs_results
        .iter()
        .filter_map(|(_, o)| match &o.rs_eq_ind {
            ring_switch::RsEqInd::Dense(v) => Some(v.as_slice()),
            _ => None,
        })
        .collect();
    // Deferred-dense claims (fused fast path): the per-claim `γ_k·B_k` buffer
    // was never materialized — fold each slot on the fly below and accumulate
    // straight into `b_combined`, saving a 2^(m-7) materialize + readback per
    // claim. Carries (eq_lo, eq_hi, γ-baked table, log₂ B).
    let rs_deferred: Vec<(&[F128], &[F128], &[F128], usize)> = rs_results
        .iter()
        .filter_map(|(_, o)| match &o.rs_eq_ind {
            ring_switch::RsEqInd::DeferredDense {
                eq_lo,
                eq_hi,
                table,
            } => Some((
                eq_lo.as_slice(),
                eq_hi.as_slice(),
                table.as_slice(),
                eq_lo.len().trailing_zeros() as usize,
            )),
            _ => None,
        })
        .collect();
    let pd_dense: Vec<(&[F128], F128)> = packed_direct
        .iter()
        .zip(gammas_pd.iter())
        .filter_map(|(pd, g)| match &pd.eq_ind {
            DirectEqInd::Dense(v) => Some((v.as_slice(), *g)),
            _ => None,
        })
        .collect();

    // ---- Build b_combined (γ-weighted sum of all rs_eq_ind + eq_ind) and the
    //      BaseFold round-0 prime (u_0, u_2 over packed_witness · b_combined).
    let mut b_combined: Vec<F128> = crate::scratch::take_f128(l);

    // Fast path (compression-proof open: claims ab, c): every RS claim is a
    // fused DeferredDense fold and there are no packed-direct claims. Fold all
    // claims block-by-block straight into b_combined — each claim's `e_hi`
    // hoisted once per block, exactly as in `fold_b128_elems_split` — and fuse
    // the round-0 prime in the same pass. Neither the per-claim `γ_k·B_k` buffer
    // nor a combine readback is ever materialized (saves ~2·L writes + 2·L reads
    // of the 2^(m-7) basis).
    let use_fast = packed_direct.is_empty()
        && !rs_deferred.is_empty()
        && rs_deferred.len() == rs_results.len();

    let (mut round0_u0, mut round0_u2) = if use_fast {
        let b = rs_deferred[0].0.len(); // eq_lo.len(); shared across claims (same split)
        debug_assert!(b >= 2 && b.is_multiple_of(2));
        debug_assert!(rs_deferred.iter().all(|d| d.0.len() == b));
        b_combined
            .par_chunks_mut(b)
            .enumerate()
            .map(|(hi, out_block)| {
                // Accumulate each claim's block: first claim writes, rest add.
                // `e_hi` is read once per claim per block, then swept over eq_lo.
                for (ci, (eq_lo, eq_hi, table, _)) in rs_deferred.iter().enumerate() {
                    let e_hi = eq_hi[hi];
                    if ci == 0 {
                        for (slot, &lo) in out_block.iter_mut().zip(eq_lo.iter()) {
                            *slot = ring_switch::fold_one_slot(lo * e_hi, table);
                        }
                    } else {
                        for (slot, &lo) in out_block.iter_mut().zip(eq_lo.iter()) {
                            *slot += ring_switch::fold_one_slot(lo * e_hi, table);
                        }
                    }
                }
                // Round-0 prime over this block's pairs (b is even, base is even).
                let base = hi * b;
                let mut u0 = F128::ZERO;
                let mut u2 = F128::ZERO;
                for t in 0..(b / 2) {
                    let s0 = out_block[2 * t];
                    let s1 = out_block[2 * t + 1];
                    let a0 = packed_witness[base + 2 * t];
                    let a1 = packed_witness[base + 2 * t + 1];
                    u0 += a0 * s0;
                    u2 += (a0 + a1) * (s0 + s1);
                }
                (u0, u2)
            })
            .reduce(
                || (F128::ZERO, F128::ZERO),
                |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2),
            )
    } else {
        // General path (mixed / sparse / packed-direct): materialize any
        // deferred-dense claims (parallel block fold), then the per-element
        // combine over all dense buffers + packed-direct, matching the
        // original behavior.
        let materialized: Vec<Vec<F128>> = rs_results
            .iter()
            .filter_map(|(_, o)| match &o.rs_eq_ind {
                ring_switch::RsEqInd::DeferredDense {
                    eq_lo,
                    eq_hi,
                    table,
                } => Some(ring_switch::fold_b128_from_table(eq_lo, eq_hi, table)),
                _ => None,
            })
            .collect();
        let mut rs_dense_all: Vec<&[F128]> = rs_baked.clone();
        rs_dense_all.extend(materialized.iter().map(|v| v.as_slice()));
        let prime = b_combined
            .par_chunks_mut(2)
            .enumerate()
            .map(|(i, chunk)| {
                let mut b0 = F128::ZERO;
                let mut b1 = F128::ZERO;
                for v in rs_dense_all.iter() {
                    b0 += v[2 * i];
                    b1 += v[2 * i + 1];
                }
                for (v, g) in pd_dense.iter() {
                    b0 += *g * v[2 * i];
                    b1 += *g * v[2 * i + 1];
                }
                chunk[0] = b0;
                chunk[1] = b1;
                let a0 = packed_witness[2 * i];
                let a1 = packed_witness[2 * i + 1];
                (a0 * b0, (a0 + a1) * (b0 + b1))
            })
            .reduce(
                || (F128::ZERO, F128::ZERO),
                |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2),
            );
        for v in materialized {
            crate::scratch::give_f128(v);
        }
        prime
    };
    let mut adjust_prime_for_delta = |idx: usize, delta: F128| {
        let pair = idx / 2;
        let a0 = packed_witness[2 * pair];
        let a1 = packed_witness[2 * pair + 1];
        if idx & 1 == 0 {
            round0_u0 += a0 * delta;
        }
        round0_u2 += (a0 + a1) * delta;
    };
    for (_, output) in rs_results.iter() {
        if let ring_switch::RsEqInd::Sparse { entries, .. } = &output.rs_eq_ind {
            for &(idx, val) in entries {
                b_combined[idx] += val;
                adjust_prime_for_delta(idx, val);
            }
        }
    }
    for (pd, g) in packed_direct.iter().zip(gammas_pd.iter()) {
        if let DirectEqInd::Sparse(eq) = &pd.eq_ind {
            sparse_scatter_add_parallel(&mut b_combined, eq, *g);
            let (u0_fix, u2_fix) = b_combined
                .par_chunks(2)
                .enumerate()
                .map(|(i, chunk)| {
                    let a0 = packed_witness[2 * i];
                    let a1 = packed_witness[2 * i + 1];
                    (a0 * chunk[0], (a0 + a1) * (chunk[0] + chunk[1]))
                })
                .reduce(
                    || (F128::ZERO, F128::ZERO),
                    |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2),
                );
            round0_u0 = u0_fix;
            round0_u2 = u2_fix;
        }
    }
    if trace {
        eprintln!(
            "  [open_batch] combine rs_eq_ind (L={}, rs×{}, pd×{}): {:6.2} ms",
            l,
            n_rs,
            n_pd,
            t.elapsed().as_secs_f64() * 1e3
        );
    }

    CombinedClaim {
        ring_switches: rs_results
            .into_iter()
            .map(|(p, o)| {
                // The per-claim rs_eq_ind (L F128s) dies here — recycle it.
                if let ring_switch::RsEqInd::Dense(v) = o.rs_eq_ind {
                    crate::scratch::give_f128(v);
                }
                p
            })
            .collect(),
        b_combined,
        target_combined,
        round0_prime: (round0_u0, round0_u2),
    }
}

/// Parallel sparse scatter-add: `b_combined[scatter_idx(c)] += gamma * eq.live_tensor[c]`
/// for every `c`. Partitions `c`-space across rayon threads; since
/// [`SparseEqTensor::scatter_idx`] is monotonic in `c` (live_positions sorted
/// ascending), each thread's scattered indices fall in a contiguous, disjoint
/// range of `b_combined`. Splits `b_combined` at the chunk boundaries via
/// `split_at_mut`, then writes scatter-adds into the disjoint mutable slices —
/// safe rust, no atomics.
fn sparse_scatter_add_parallel(b_combined: &mut [F128], eq: &SparseEqTensor, gamma: F128) {
    use rayon::prelude::*;

    let c_total = eq.live_tensor.len();
    if c_total == 0 {
        return;
    }
    let n_threads = rayon::current_num_threads().max(1);
    let c_per_chunk = c_total.div_ceil(n_threads).max(1);
    let actual_n_chunks = c_total.div_ceil(c_per_chunk);

    // Boundaries in `b_combined` index space. `b_boundaries[i]` is where chunk
    // `i` starts. `b_boundaries[i+1] − b_boundaries[i]` is chunk `i`'s slice
    // length. The last chunk extends to `b_combined.len()` to absorb any tail
    // positions beyond the maximum scatter idx (those contain only dense
    // contributions from the parallel pass).
    let b_boundaries: Vec<usize> = (0..=actual_n_chunks)
        .map(|i| {
            if i == 0 {
                0
            } else if i == actual_n_chunks {
                b_combined.len()
            } else {
                eq.scatter_idx(i * c_per_chunk)
            }
        })
        .collect();
    debug_assert!(b_boundaries.windows(2).all(|w| w[0] <= w[1]));

    // Disjoint mutable slices via repeated split_at_mut.
    let mut remaining: &mut [F128] = b_combined;
    let mut slices: Vec<&mut [F128]> = Vec::with_capacity(actual_n_chunks);
    for i in 1..actual_n_chunks {
        let split_at = b_boundaries[i] - b_boundaries[i - 1];
        let (left, right) = remaining.split_at_mut(split_at);
        slices.push(left);
        remaining = right;
    }
    slices.push(remaining);
    debug_assert_eq!(slices.len(), actual_n_chunks);

    slices.into_par_iter().enumerate().for_each(|(t, slice)| {
        let c_lo = t * c_per_chunk;
        let c_hi = ((t + 1) * c_per_chunk).min(c_total);
        let b_lo = b_boundaries[t];
        for c in c_lo..c_hi {
            let val = eq.live_tensor[c];
            let idx = eq.scatter_idx(c);
            slice[idx - b_lo] += gamma * val;
        }
    });
}

/// Verify a batched opening produced by [`open_batch`]. Each `(claim, z_skip,
/// x_outer)` triple is checked via its own ring-switching message; then the
/// random-linear-combination of their `rs_eq_ind`s is verified against the
/// single BaseFold proof.
pub fn verify_opening_batch<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[F128],
    z_skips: &[F128],
    x_outers: &[&[F128]],
    proof: &BatchOpeningProof,
    challenger: &mut Ch,
) -> Result<(), VerifyError> {
    verify_opening_batch_mixed(
        commitment,
        claims,
        z_skips,
        x_outers,
        &[],
        proof,
        challenger,
    )
}

/// Verifier reference to a packed-direct claim: the multilinear point at
/// which `ẑ_packed` was claimed equal to `value`. The verifier owns the data
/// (it appears in the public statement of whatever produced the claim, e.g.
/// the chain shift sumcheck output).
#[derive(Clone, Copy, Debug)]
pub struct PackedDirectClaimRef<'a> {
    pub point: &'a [F128],
    pub value: F128,
}

/// Verify a mixed-claim batched opening. Mirror of [`open_batch_mixed`].
#[allow(clippy::too_many_arguments)]
pub fn verify_opening_batch_mixed<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[F128],
    z_skips: &[F128],
    x_outers: &[&[F128]],
    packed_direct: &[PackedDirectClaimRef<'_>],
    proof: &BatchOpeningProof,
    challenger: &mut Ch,
) -> Result<(), VerifyError> {
    let n_rs = claims.len();
    let n_pd = packed_direct.len();
    assert_eq!(z_skips.len(), n_rs);
    assert_eq!(x_outers.len(), n_rs);
    assert_eq!(proof.ring_switches.len(), n_rs);
    assert!(
        n_rs + n_pd > 0,
        "verify_opening_batch_mixed: need at least one claim"
    );

    challenger.observe_label(b"history-pcs-open-batch-v0");

    let trace = std::env::var("VERIFY_TRACE").is_ok();
    let fmt = |s: f64| -> String {
        let ms = s * 1000.0;
        if ms < 1.0 {
            format!("{:>8.2} µs", s * 1e6)
        } else {
            format!("{:>8.2} ms", ms)
        }
    };

    // 1. Ring-switch verify per ring-switched claim (succinct: skip dense
    //    rs_eq_ind alloc). After all RS claims are observed, sample γ_rs —
    //    matches the prover's `prove_batched_padded_with_precomputed` which
    //    samples γ_rs at the same transcript point and bakes it into the fold.
    let t = std::time::Instant::now();
    let mut rs_outputs = Vec::with_capacity(n_rs);
    for i in 0..n_rs {
        let out = ring_switch::verify_succinct(
            claims[i],
            z_skips[i],
            x_outers[i],
            &proof.ring_switches[i],
            challenger,
        )
        .map_err(VerifyError::RingSwitch)?;
        rs_outputs.push(out);
    }
    let gammas_rs: Vec<F128> = (0..n_rs).map(|_| challenger.sample_f128()).collect();
    if trace {
        eprintln!(
            "      [pcsv] ring_switch::verify_succinct ×{}: {}",
            n_rs,
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // 2. Observe packed-direct claim values, then sample γ_pd (Schwartz-
    //    Zippel-sound: γ_pd[k] is sampled after pd.value[k] is observed).
    for pd in packed_direct {
        challenger.observe_label(b"history-pcs-packed-direct-v0");
        challenger.observe_f128(pd.value);
    }
    let gammas_pd: Vec<F128> = (0..n_pd).map(|_| challenger.sample_f128()).collect();

    // 4. Combined target: γ_rs · sumcheck_claim_rs + γ_pd · value_pd.
    let mut target_combined = F128::ZERO;
    for (out, g) in rs_outputs.iter().zip(gammas_rs.iter()) {
        target_combined += *g * out.sumcheck_claim;
    }
    for (pd, g) in packed_direct.iter().zip(gammas_pd.iter()) {
        target_combined += *g * pd.value;
    }

    // 5. BaseFold verify against combined target.
    let t = std::time::Instant::now();
    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    if trace {
        eprintln!(
            "      [pcsv] AdditiveNttF128::standard: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }
    let t = std::time::Instant::now();
    let challenges = basefold::verify_with_node_hash(
        target_combined,
        &proof.basefold,
        &commitment.root,
        &ntt,
        commitment.params.log_msg_len(),
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        challenger,
        commitment.params.node_hash_version(),
    )
    .map_err(VerifyError::BaseFold)?;
    if trace {
        eprintln!(
            "      [pcsv] basefold::verify: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // 6. `final_b` must equal Σ_rs γ_rs · MLE(rs_eq_ind, challenges) + Σ_pd γ_pd ·
    //    eq_eval(point, challenges). Ring-switched uses the DP24 succinct
    //    recurrence; packed-direct uses the standard multilinear eq evaluation.
    let t = std::time::Instant::now();
    let mut expected_final_b = F128::ZERO;
    for (out, (g, x_outer)) in rs_outputs.iter().zip(gammas_rs.iter().zip(x_outers.iter())) {
        expected_final_b +=
            *g * ring_switch::eval_rs_eq(&x_outer[1..], &challenges, &out.eq_r_dprime);
    }
    // Packed-direct: γ_pd · eq_eval(point, basefold_challenges). The basefold
    // challenges have length L = m − 7, matching the packed-direct point.
    for (pd, g) in packed_direct.iter().zip(gammas_pd.iter()) {
        expected_final_b += *g * crate::zerocheck::multilinear::eq_eval(pd.point, &challenges);
    }
    if trace {
        eprintln!(
            "      [pcsv] eval_rs_eq ×{} + eq_eval pd×{}: {}",
            n_rs,
            n_pd,
            fmt(t.elapsed().as_secs_f64())
        );
    }
    if expected_final_b != proof.basefold.final_b {
        return Err(VerifyError::FinalBMismatch);
    }
    Ok(())
}

/// Ligerito-backend mirror of [`verify_opening_batch_mixed`]. Uses
/// `ring_switch::verify` (non-succinct, so it returns the dense `rs_eq_ind`)
/// to reconstruct `b_combined`, then delegates to
/// [`ligerito::recursive_verifier_with_basis`].
///
/// NOTE: this is the simple (non-succinct) verifier path; it materializes
/// the full `2^(m-7)` rs_eq_ind, costing ~16 MB at m=29. A succinct variant
/// (DP24-style polylog reconstruction at the residual point only) is a
/// natural follow-up — would bring verifier cost in line with the basefold
/// succinct path.
#[allow(clippy::too_many_arguments)]
pub fn verify_opening_batch_ligerito_mixed<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[F128],
    z_skips: &[F128],
    x_outers: &[&[F128]],
    packed_direct: &[PackedDirectClaimRef<'_>],
    proof: &BatchOpeningProofLigerito,
    lig_config: &ligerito::VerifierConfig,
    challenger: &mut Ch,
) -> Result<(), VerifyError> {
    let n_rs = claims.len();
    let n_pd = packed_direct.len();
    assert_eq!(z_skips.len(), n_rs);
    assert_eq!(x_outers.len(), n_rs);
    assert_eq!(proof.ring_switches.len(), n_rs);
    assert!(n_rs + n_pd > 0);

    challenger.observe_label(b"history-pcs-open-batch-v0");

    // 1. Ring-switch SUCCINCT verify per claim — gets sumcheck_claim and a
    //    length-128 `eq_r_dprime` instead of the dense `rs_eq_ind`. Saves
    //    ~16 MB allocation at m=29.
    let mut rs_outputs = Vec::with_capacity(n_rs);
    for i in 0..n_rs {
        let out = ring_switch::verify_succinct(
            claims[i],
            z_skips[i],
            x_outers[i],
            &proof.ring_switches[i],
            challenger,
        )
        .map_err(VerifyError::RingSwitch)?;
        rs_outputs.push(out);
    }
    let gammas_rs: Vec<F128> = (0..n_rs).map(|_| challenger.sample_f128()).collect();

    // 2. PD claim values + γ_pd.
    for pd in packed_direct {
        challenger.observe_label(b"history-pcs-packed-direct-v0");
        challenger.observe_f128(pd.value);
    }
    let gammas_pd: Vec<F128> = (0..n_pd).map(|_| challenger.sample_f128()).collect();

    // 3. target_combined from succinct rs claims + PD values.
    let mut target_combined = F128::ZERO;
    for (out, g) in rs_outputs.iter().zip(gammas_rs.iter()) {
        target_combined += *g * out.sumcheck_claim;
    }
    for (pd, g) in packed_direct.iter().zip(gammas_pd.iter()) {
        target_combined += *g * pd.value;
    }

    // 4. Batch evaluator: returns b_combined at all yr positions in one call.
    //    For RS claims, precompute the ring_switch tensor PREFIX once (over
    //    the ris part) and only re-do the yr_log_n-step suffix per y.
    //    For PD claims, precompute eq prefix factors over ris and finish per y.
    //    Prefix reuse avoids rebuilding the shared ris tensor for every y.
    let log_n = commitment.params.m - LOG_PACKING;
    let eval_b_residual = |ris: &[F128], yr_log_n: usize| -> Vec<F128> {
        use crate::zerocheck::multilinear::eq_eval;
        let yr_len = 1usize << yr_log_n;
        let prefix_len = ris.len();

        // ---- RS claim prefixes ----
        let rs_prefixes: Vec<crate::pcs::tensor_algebra::TensorAlgebra> = rs_outputs
            .iter()
            .zip(x_outers.iter())
            .map(|(_out, x_outer)| {
                // x_outer[1..] has length log_n; we feed only the ris prefix.
                ring_switch::eval_rs_eq_prefix(&x_outer[1..1 + prefix_len], ris)
            })
            .collect();

        // ---- PD claim prefix scalars ----
        // eq(pd.point, point) factors over coordinates; precompute the prefix product.
        let pd_prefix_scalars: Vec<F128> = packed_direct
            .iter()
            .map(|pd| eq_eval(&pd.point[..prefix_len], ris))
            .collect();

        // ---- Per-y assembly (parallel over yr positions; each y is independent).
        //      y_suffix is binary (bits of y), so we use the binary-query
        //      specializations of eval_rs_eq_finish / eq_eval — each suffix
        //      step collapses to a single scale_vertical / scalar product.
        use rayon::prelude::*;
        debug_assert!(yr_log_n <= 32, "yr_log_n > 32 not supported by binary path");
        (0..yr_len)
            .into_par_iter()
            .map(|y| {
                let y_bits = y as u32;
                let mut sum = F128::ZERO;
                for (((out, g), x_outer), prefix) in rs_outputs
                    .iter()
                    .zip(gammas_rs.iter())
                    .zip(x_outers.iter())
                    .zip(rs_prefixes.iter())
                {
                    sum += *g
                        * ring_switch::eval_rs_eq_finish_from_prefix_binary_q(
                            prefix,
                            &x_outer[1 + prefix_len..],
                            y_bits,
                            &out.eq_r_dprime,
                        );
                }
                for ((pd, g), prefix_scalar) in packed_direct
                    .iter()
                    .zip(gammas_pd.iter())
                    .zip(pd_prefix_scalars.iter())
                {
                    sum += *g
                        * *prefix_scalar
                        * crate::zerocheck::multilinear::eq_eval_binary_x(
                            &pd.point[prefix_len..],
                            y_bits,
                        );
                }
                sum
            })
            .collect()
    };

    // 5. Drive ligerito SUCCINCT verifier — eval_b_residual is called ONCE
    //    at the residual check (returns all yr_len values in one batch).
    let ok = ligerito::recursive_verifier_with_basis_succinct(
        lig_config,
        &proof.ligerito,
        log_n,
        target_combined,
        &commitment.root,
        eval_b_residual,
        challenger,
    );
    if !ok {
        return Err(VerifyError::BaseFold(
            crate::pcs::basefold::VerifyError::InvalidProofShape,
        ));
    }
    Ok(())
}

/// Verify an opening proof against the commitment. Returns `Ok(())` iff valid.
pub fn verify_opening<Ch: Challenger>(
    commitment: &Commitment,
    claim: F128,
    z_skip: F128,
    x_outer: &[F128],
    proof: &OpeningProof,
    challenger: &mut Ch,
) -> Result<(), VerifyError> {
    challenger.observe_label(b"history-pcs-open-v0");

    // Ring-switching (succinct): claim → sumcheck_claim + eq_r_dprime. The
    // dense rs_eq_ind is never materialized on the verifier side.
    let rs_output =
        ring_switch::verify_succinct(claim, z_skip, x_outer, &proof.ring_switch, challenger)
            .map_err(VerifyError::RingSwitch)?;

    // BaseFold sumcheck + FRI: sumcheck_claim → verified final_a · final_b.
    let ntt = crate::ntt::AdditiveNttF128::standard(commitment.params.k_code());
    let challenges = basefold::verify_with_node_hash(
        rs_output.sumcheck_claim,
        &proof.basefold,
        &commitment.root,
        &ntt,
        commitment.params.log_msg_len(),
        commitment.params.log_inv_rate,
        commitment.params.log_batch_size,
        challenger,
        commitment.params.node_hash_version(),
    )
    .map_err(VerifyError::BaseFold)?;

    // Independent check: final_b should equal MLE(rs_eq_ind)(challenges).
    // Computed succinctly via the DP24 tensor-algebra recurrence (polylog in
    // witness size), instead of materializing rs_eq_ind densely.
    let expected_final_b =
        ring_switch::eval_rs_eq(&x_outer[1..], &challenges, &rs_output.eq_r_dprime);
    if expected_final_b != proof.basefold.final_b {
        return Err(VerifyError::FinalBMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::{FsChallenger, FsLaneChallenger};
    use crate::zerocheck::multilinear::lagrange_weights_naive;
    use crate::zerocheck::univariate_skip::build_eq;

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn bits(&mut self, n: usize) -> Vec<bool> {
            (0..n).map(|_| self.next_u64() & 1 == 1).collect()
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

    fn default_params(m: usize) -> PcsParams {
        PcsParams {
            m,
            // Tiny algebra/codec fixtures still enter the same fail-closed
            // finite-length BaseFold configuration path. Rate 1/32 keeps
            // their smallest n=32 domain inside the reviewed UDR range.
            log_inv_rate: 5,
            log_batch_size: 1,
            profile: Default::default(),
        }
    }

    fn zhat_skip_reference(z: &[bool], m: usize, z_skip: F128, x_outer: &[F128]) -> F128 {
        const K_SKIP: usize = 6;
        let ell = 1usize << K_SKIP;
        let lambda = lagrange_weights_naive(K_SKIP, z_skip);
        let eq_outer = build_eq(x_outer);
        let mut acc = F128::ZERO;
        for i_outer in 0..(1usize << (m - K_SKIP)) {
            let base = i_outer * ell;
            let mut inner = F128::ZERO;
            for i_skip in 0..ell {
                if z[base + i_skip] {
                    inner += lambda[i_skip];
                }
            }
            acc += eq_outer[i_outer] * inner;
        }
        acc
    }

    /// End-to-end PCS roundtrip: commit, open at a random QuirkyPoint, verify.
    #[test]
    fn pcs_open_verify_roundtrip() {
        let mut rng = Rng::new(0xC0FFEE_42);
        for &m in &[8usize, 9, 10, 11] {
            let z = rng.bits(1 << m);
            let z_skip = rng.f128();
            let x_outer: Vec<F128> = (0..(m - 6)).map(|_| rng.f128()).collect();
            let claim = zhat_skip_reference(&z, m, z_skip, &x_outer);

            let params = default_params(m);
            let z_packed = pack_witness(&z, m);
            let (commitment, prover_data) = commit(&z_packed, &params);

            let mut ch_p = FsChallenger::new(b"history-test-v0");
            let proof = open(&z_packed, &prover_data, &commitment, &x_outer, &mut ch_p);

            let mut ch_v = FsChallenger::new(b"history-test-v0");
            verify_opening(&commitment, claim, z_skip, &x_outer, &proof, &mut ch_v)
                .unwrap_or_else(|e| panic!("verify rejected honest proof at m={m}: {e:?}"));
        }
    }

    #[test]
    fn pcs_verify_rejects_wrong_claim() {
        let m = 10;
        let mut rng = Rng::new(0x99);
        let z = rng.bits(1 << m);
        let z_skip = rng.f128();
        let x_outer: Vec<F128> = (0..(m - 6)).map(|_| rng.f128()).collect();
        let mut claim = zhat_skip_reference(&z, m, z_skip, &x_outer);
        claim.lo ^= 1;

        let params = default_params(m);
        let z_packed = pack_witness(&z, m);
        let (commitment, prover_data) = commit(&z_packed, &params);

        let mut ch_p = FsChallenger::new(b"history-test-v0");
        let proof = open(&z_packed, &prover_data, &commitment, &x_outer, &mut ch_p);

        let mut ch_v = FsChallenger::new(b"history-test-v0");
        let res = verify_opening(&commitment, claim, z_skip, &x_outer, &proof, &mut ch_v);
        assert!(matches!(res, Err(VerifyError::RingSwitch(_))));
    }

    #[test]
    fn pcs_verify_rejects_mutated_basefold() {
        let m = 10;
        let mut rng = Rng::new(0xABCD);
        let z = rng.bits(1 << m);
        let z_skip = rng.f128();
        let x_outer: Vec<F128> = (0..(m - 6)).map(|_| rng.f128()).collect();
        let claim = zhat_skip_reference(&z, m, z_skip, &x_outer);

        let params = default_params(m);
        let z_packed = pack_witness(&z, m);
        let (commitment, prover_data) = commit(&z_packed, &params);

        let mut ch_p = FsChallenger::new(b"history-test-v0");
        let mut proof = open(&z_packed, &prover_data, &commitment, &x_outer, &mut ch_p);
        // Mutate final_a: now caught by either sumcheck or FRI consistency.
        proof.basefold.final_a.lo ^= 1;

        let mut ch_v = FsChallenger::new(b"history-test-v0");
        let res = verify_opening(&commitment, claim, z_skip, &x_outer, &proof, &mut ch_v);
        assert!(matches!(res, Err(VerifyError::BaseFold(_))));
    }

    /// SECURITY REGRESSION: a prover that strips FRI queries (down to zero)
    /// must be rejected. Without the query-count enforcement in
    /// `basefold::verify`, an empty/truncated query set leaves `final_a`
    /// unbound to the committed codeword, so any evaluation claim verifies.
    #[test]
    fn pcs_verify_rejects_truncated_fri_queries() {
        let m = 10;
        let mut rng = Rng::new(0x5EC0_1234);
        let z = rng.bits(1 << m);
        let z_skip = rng.f128();
        let x_outer: Vec<F128> = (0..(m - 6)).map(|_| rng.f128()).collect();
        let claim = zhat_skip_reference(&z, m, z_skip, &x_outer);

        let params = default_params(m);
        let z_packed = pack_witness(&z, m);
        let (commitment, prover_data) = commit(&z_packed, &params);

        let mut ch_p = FsChallenger::new(b"history-test-v0");
        let honest = open(&z_packed, &prover_data, &commitment, &x_outer, &mut ch_p);

        // The honest proof must verify (sanity: the enforcement is not over-tight).
        let mut ch_ok = FsChallenger::new(b"history-test-v0");
        assert!(verify_opening(&commitment, claim, z_skip, &x_outer, &honest, &mut ch_ok).is_ok());

        // Attack: truncate the query set to a handful, and to zero. Both must
        // be rejected on proof shape before any position is sampled.
        for keep in [0usize, 1, 8] {
            let mut proof = honest.clone();
            proof.basefold.queries.truncate(keep);
            let mut ch_v = FsChallenger::new(b"history-test-v0");
            let res = verify_opening(&commitment, claim, z_skip, &x_outer, &proof, &mut ch_v);
            assert!(
                matches!(
                    res,
                    Err(VerifyError::BaseFold(
                        basefold::VerifyError::InvalidProofShape
                    ))
                ),
                "truncating to {keep} queries must be rejected, got {res:?}"
            );
        }
    }

    /// SECURITY REGRESSION: the sumcheck depth (`log_msg_len`) is a
    /// commitment parameter; a proof carrying a different number of round
    /// messages must be rejected on shape, not allowed to redefine every
    /// downstream size (epoch arities, query masks, challenge count) —
    /// mismatches used to surface as release-mode panics in the caller.
    #[test]
    fn pcs_verify_rejects_wrong_sumcheck_depth() {
        let m = 10;
        let mut rng = Rng::new(0x0DD_D3B7);
        let z = rng.bits(1 << m);
        let z_skip = rng.f128();
        let x_outer: Vec<F128> = (0..(m - 6)).map(|_| rng.f128()).collect();
        let claim = zhat_skip_reference(&z, m, z_skip, &x_outer);

        let params = default_params(m);
        let z_packed = pack_witness(&z, m);
        let (commitment, prover_data) = commit(&z_packed, &params);

        let mut ch_p = FsChallenger::new(b"history-test-v0");
        let honest = open(&z_packed, &prover_data, &commitment, &x_outer, &mut ch_p);

        let mut ch_ok = FsChallenger::new(b"history-test-v0");
        assert!(verify_opening(&commitment, claim, z_skip, &x_outer, &honest, &mut ch_ok).is_ok());

        // Truncated and extended round-message vectors must both be shape
        // errors before any challenge is drawn from them.
        let mut truncated = honest.clone();
        truncated.basefold.round_messages.pop();
        let mut extended = honest.clone();
        let extra = extended.basefold.round_messages[0].clone();
        extended.basefold.round_messages.push(extra);

        for (label, proof) in [("truncated", truncated), ("extended", extended)] {
            let mut ch_v = FsChallenger::new(b"history-test-v0");
            let res = verify_opening(&commitment, claim, z_skip, &x_outer, &proof, &mut ch_v);
            assert!(
                matches!(
                    res,
                    Err(VerifyError::BaseFold(
                        basefold::VerifyError::InvalidProofShape
                    ))
                ),
                "{label} round messages must be a shape error, got {res:?}"
            );
        }
    }

    /// Direct multilinear evaluation of `ẑ_packed` (the F_{2^128}-packed
    /// witness) at a length-L point. Reference computation for the
    /// packed-direct claim path.
    fn zhat_packed_reference(z_packed: &[F128], point: &[F128]) -> F128 {
        let l = point.len();
        assert_eq!(z_packed.len(), 1usize << l);
        let eq = build_eq(point);
        let mut acc = F128::ZERO;
        for i in 0..z_packed.len() {
            acc += eq[i] * z_packed[i];
        }
        acc
    }

    /// Roundtrip a single packed-direct claim through `open_batch_mixed` /
    /// `verify_opening_batch_mixed`. Dense `eq_ind`.
    #[test]
    fn pcs_packed_direct_dense_roundtrip() {
        let mut rng = Rng::new(0xDEAD_BEEF);
        for &m in &[8usize, 10, 11] {
            let l = m - LOG_PACKING; // = m - 7
            let z = rng.bits(1 << m);
            let z_packed = pack_witness(&z, m);

            let point: Vec<F128> = (0..l).map(|_| rng.f128()).collect();
            let value = zhat_packed_reference(&z_packed, &point);
            let eq = build_eq(&point);

            let pd_claim = PackedDirectClaim {
                point: point.clone(),
                value,
                eq_ind: DirectEqInd::Dense(eq),
            };

            let params = default_params(m);
            let (commitment, prover_data) = commit(&z_packed, &params);

            let mut ch_p = FsChallenger::new(b"history-test-v0");
            let proof = open_batch_mixed(
                &z_packed,
                &prover_data,
                &commitment,
                &[],
                std::slice::from_ref(&pd_claim),
                &PaddingSpec::dense(m),
                &mut ch_p,
            );

            let pd_ref = PackedDirectClaimRef {
                point: &point,
                value,
            };
            let mut ch_v = FsChallenger::new(b"history-test-v0");
            verify_opening_batch_mixed(
                &commitment,
                &[],
                &[],
                &[],
                std::slice::from_ref(&pd_ref),
                &proof,
                &mut ch_v,
            )
            .unwrap_or_else(|e| panic!("verify rejected honest packed-direct claim m={m}: {e:?}"));

            // Wrong claim is rejected.
            let mut bad_value = value;
            bad_value.lo ^= 1;
            let pd_bad = PackedDirectClaimRef {
                point: &point,
                value: bad_value,
            };
            let mut ch_v = FsChallenger::new(b"history-test-v0");
            let res = verify_opening_batch_mixed(
                &commitment,
                &[],
                &[],
                &[],
                std::slice::from_ref(&pd_bad),
                &proof,
                &mut ch_v,
            );
            assert!(matches!(
                res,
                Err(VerifyError::FinalBMismatch) | Err(VerifyError::BaseFold(_))
            ));
        }
    }

    /// Roundtrip with sparse `eq_ind` (some zero coords in the point).
    #[test]
    fn pcs_packed_direct_sparse_roundtrip() {
        let mut rng = Rng::new(0xFACE_F00D);
        for &m in &[10usize, 11] {
            let l = m - LOG_PACKING;
            let z = rng.bits(1 << m);
            let z_packed = pack_witness(&z, m);

            // Build a point with the last 2 coords zero (sparse pattern).
            let mut point: Vec<F128> = (0..l).map(|_| rng.f128()).collect();
            for slot in point.iter_mut().rev().take(2) {
                *slot = F128::ZERO;
            }
            let value = zhat_packed_reference(&z_packed, &point);
            let sparse_eq = ring_switch::build_eq_sparse(&point);

            let pd_claim = PackedDirectClaim {
                point: point.clone(),
                value,
                eq_ind: DirectEqInd::Sparse(sparse_eq),
            };

            let params = default_params(m);
            let (commitment, prover_data) = commit(&z_packed, &params);

            let mut ch_p = FsChallenger::new(b"history-test-v0");
            let proof = open_batch_mixed(
                &z_packed,
                &prover_data,
                &commitment,
                &[],
                std::slice::from_ref(&pd_claim),
                &PaddingSpec::dense(m),
                &mut ch_p,
            );

            let pd_ref = PackedDirectClaimRef {
                point: &point,
                value,
            };
            let mut ch_v = FsChallenger::new(b"history-test-v0");
            verify_opening_batch_mixed(
                &commitment,
                &[],
                &[],
                &[],
                std::slice::from_ref(&pd_ref),
                &proof,
                &mut ch_v,
            )
            .unwrap_or_else(|e| panic!("verify rejected honest sparse packed-direct m={m}: {e:?}"));
        }
    }

    /// Mixed batch: one ring-switched claim + one packed-direct claim against
    /// the same commitment must both verify.
    #[test]
    fn pcs_mixed_ring_switched_and_packed_direct() {
        let m = 11usize;
        let l = m - LOG_PACKING;
        let mut rng = Rng::new(0xCAFE_BABE);
        let z = rng.bits(1 << m);
        let z_packed = pack_witness(&z, m);

        // Ring-switched claim.
        let z_skip = rng.f128();
        let x_outer: Vec<F128> = (0..(m - 6)).map(|_| rng.f128()).collect();
        let rs_claim = zhat_skip_reference(&z, m, z_skip, &x_outer);

        // Packed-direct claim.
        let pd_point: Vec<F128> = (0..l).map(|_| rng.f128()).collect();
        let pd_value = zhat_packed_reference(&z_packed, &pd_point);
        let pd_eq = build_eq(&pd_point);
        let pd_claim = PackedDirectClaim {
            point: pd_point.clone(),
            value: pd_value,
            eq_ind: DirectEqInd::Dense(pd_eq),
        };

        let params = default_params(m);
        let (commitment, prover_data) = commit(&z_packed, &params);

        let mut ch_p = FsChallenger::new(b"history-test-v0");
        let proof = open_batch_mixed(
            &z_packed,
            &prover_data,
            &commitment,
            &[x_outer.as_slice()],
            std::slice::from_ref(&pd_claim),
            &PaddingSpec::dense(m),
            &mut ch_p,
        );

        let pd_ref = PackedDirectClaimRef {
            point: &pd_point,
            value: pd_value,
        };
        let mut ch_v = FsChallenger::new(b"history-test-v0");
        verify_opening_batch_mixed(
            &commitment,
            &[rs_claim],
            &[z_skip],
            &[x_outer.as_slice()],
            std::slice::from_ref(&pd_ref),
            &proof,
            &mut ch_v,
        )
        .unwrap_or_else(|e| panic!("mixed batch verify rejected honest proof: {e:?}"));
    }

    /// End-to-end Ligerito backend roundtrip through pcs::open_batch_mixed_ligerito
    /// and verify_opening_batch_ligerito_mixed. Single ring-switched claim
    /// (no PD — PD path is task #11).
    #[test]
    #[ignore] // Heavier — ~50-100 ms; run with `cargo test pcs_ligerito_roundtrip -- --ignored --nocapture`
    fn pcs_ligerito_backend_roundtrip() {
        let m = 22usize;
        let mut rng = Rng::new(0x11_6E_2170);
        let z = rng.bits(1 << m);
        let z_skip = rng.f128();
        let x_outer: Vec<F128> = (0..(m - 6)).map(|_| rng.f128()).collect();
        let rs_claim = zhat_skip_reference(&z, m, z_skip, &x_outer);

        // PcsParams MUST set log_batch_size = ligerito_initial_k for L0 reuse.
        let initial_k = 6;
        let params = PcsParams {
            m,
            log_inv_rate: 1,
            log_batch_size: initial_k,
            profile: Default::default(),
        };
        let z_packed = pack_witness(&z, m);
        let (commitment, prover_data) = commit(&z_packed, &params);

        let recursive_ks = vec![3usize, 3, 3];
        let log_inv_rates = vec![1usize, 3, 4, 6];
        let queries: Vec<usize> = log_inv_rates
            .iter()
            .map(|&r| crate::pcs::ligerito::udr_queries(r))
            .collect();
        let grinding_bits = vec![0usize; log_inv_rates.len()];
        let n_levels = log_inv_rates.len();
        let lig_p_cfg = crate::pcs::ligerito::ProverConfig {
            log_inv_rates: log_inv_rates.clone(),
            recursive_steps: recursive_ks.len(),
            initial_log_msg_cols: (m - LOG_PACKING) - initial_k,
            initial_log_num_interleaved: initial_k,
            initial_k,
            recursive_log_msg_cols: vec![6, 3, 0],
            recursive_ks: recursive_ks.clone(),
            queries: queries.clone(),
            grinding_bits: grinding_bits.clone(),
            fold_grinding_bits: vec![0; n_levels],
            ood_samples: vec![0; n_levels],
        };
        let lig_v_cfg = crate::pcs::ligerito::VerifierConfig {
            log_inv_rates,
            recursive_steps: recursive_ks.len(),
            initial_log_msg_cols: (m - LOG_PACKING) - initial_k,
            initial_log_num_interleaved: initial_k,
            initial_k,
            recursive_log_msg_cols: vec![6, 3, 0],
            recursive_ks,
            queries,
            grinding_bits,
            fold_grinding_bits: vec![0; n_levels],
            ood_samples: vec![0; n_levels],
        };

        let mut ch_p = FsChallenger::new(b"history-test-lig-v0");
        let proof = open_batch_mixed_ligerito_with_precomputed_s_hat_v(
            z_packed.clone(),
            &prover_data,
            &commitment,
            &[x_outer.as_slice()],
            &[],
            &[],
            &PaddingSpec::dense(m),
            &lig_p_cfg,
            &mut ch_p,
        );

        let mut ch_v = FsChallenger::new(b"history-test-lig-v0");
        verify_opening_batch_ligerito_mixed(
            &commitment,
            &[rs_claim],
            &[z_skip],
            &[x_outer.as_slice()],
            &[],
            &proof,
            &lig_v_cfg,
            &mut ch_v,
        )
        .unwrap_or_else(|e| panic!("ligerito verify rejected honest proof: {e:?}"));
    }

    // -----------------------------------------------------------------------
    // Quirky-direct claims (FieldR1cs path, P1)
    // -----------------------------------------------------------------------

    /// Quirky MLE evaluation of an F128-element vector at
    /// `(z_skip, x_rest)`: `Σ_i v[i] · L_{i mod 2^k}(z_skip) · eq(x_rest, i >> k)`.
    fn zhat_quirky_reference(v: &[F128], k_skip: usize, z_skip: F128, x_rest: &[F128]) -> F128 {
        let ell = 1usize << k_skip;
        assert_eq!(v.len(), ell << x_rest.len());
        let weights = crate::zerocheck::multilinear::lagrange_weights_naive(k_skip, z_skip);
        let eq = build_eq(x_rest);
        let mut acc = F128::ZERO;
        for (i, &x) in v.iter().enumerate() {
            acc += x * weights[i % ell] * eq[i / ell];
        }
        acc
    }

    /// Roundtrip two quirky-direct claims through `open_batch_quirky_direct`
    /// / `verify_opening_batch_quirky_direct`, then reject tampers.
    #[test]
    fn pcs_quirky_direct_roundtrip_and_tampers() {
        const K_SKIP: usize = 6;
        let mut rng = Rng::new(0x0F1E1D);
        for &m in &[14usize, 16] {
            let l = m - LOG_PACKING;
            // The committed vector IS the field witness (2^l F128 elements).
            let z: Vec<F128> = (0..(1usize << l)).map(|_| rng.f128()).collect();

            let mk_claim = |rng: &mut Rng| {
                let z_skip = rng.f128();
                let x_rest: Vec<F128> = (0..(l - K_SKIP)).map(|_| rng.f128()).collect();
                let value = zhat_quirky_reference(&z, K_SKIP, z_skip, &x_rest);
                QuirkyDirectClaim {
                    z_skip,
                    k_skip: K_SKIP,
                    x_rest,
                    value,
                }
            };
            let claims = vec![mk_claim(&mut rng), mk_claim(&mut rng)];

            let params = default_params(m);
            let (commitment, prover_data) = commit(&z, &params);

            let mut ch_p = FsChallenger::new(b"history-test-v0");
            let proof = open_batch_quirky_direct(&z, &prover_data, &commitment, &claims, &mut ch_p);

            let refs: Vec<QuirkyDirectClaimRef<'_>> = claims
                .iter()
                .map(|c| QuirkyDirectClaimRef {
                    z_skip: c.z_skip,
                    k_skip: c.k_skip,
                    x_rest: &c.x_rest,
                    value: c.value,
                })
                .collect();
            let mut ch_v = FsChallenger::new(b"history-test-v0");
            verify_opening_batch_quirky_direct(&commitment, &refs, &proof, &mut ch_v)
                .unwrap_or_else(|e| panic!("honest quirky-direct rejected at m={m}: {e:?}"));

            // Tamper: wrong claimed value.
            let mut bad_refs = refs.clone();
            bad_refs[0].value += F128::ONE;
            let mut ch = FsChallenger::new(b"history-test-v0");
            assert!(
                verify_opening_batch_quirky_direct(&commitment, &bad_refs, &proof, &mut ch)
                    .is_err(),
                "wrong value accepted at m={m}"
            );

            // Tamper: wrong z_skip (point substitution).
            let mut bad_refs = refs.clone();
            bad_refs[1].z_skip += F128::ONE;
            let mut ch = FsChallenger::new(b"history-test-v0");
            assert!(
                verify_opening_batch_quirky_direct(&commitment, &bad_refs, &proof, &mut ch)
                    .is_err(),
                "wrong z_skip accepted at m={m}"
            );

            // Tamper: proof final_b flip.
            let mut bad = proof.clone();
            bad.final_b += F128::ONE;
            let mut ch = FsChallenger::new(b"history-test-v0");
            assert!(
                verify_opening_batch_quirky_direct(&commitment, &refs, &bad, &mut ch).is_err(),
                "final_b tamper accepted at m={m}"
            );

            // Tamper: truncate FRI queries.
            let mut bad = proof.clone();
            bad.queries.truncate(1);
            let mut ch = FsChallenger::new(b"history-test-v0");
            assert!(
                verify_opening_batch_quirky_direct(&commitment, &refs, &bad, &mut ch).is_err(),
                "query truncation accepted at m={m}"
            );
        }
    }

    fn zhat_quirky_reference_c1(
        values: &[F128],
        k_skip: usize,
        z_skip: F256,
        x_rest: &[F256],
    ) -> F256 {
        let skip_size = 1usize << k_skip;
        assert_eq!(values.len(), skip_size << x_rest.len());
        let skip = crate::zerocheck::field_c1::lagrange_weights(k_skip, z_skip, 0);
        let rest = crate::zerocheck::field_c1::build_eq_table(x_rest);
        values
            .iter()
            .enumerate()
            .fold(F256::ZERO, |sum, (index, &value)| {
                sum + (skip[index % skip_size] * rest[index / skip_size]).scale_base(value)
            })
    }

    #[test]
    fn pcs_c1_quirky_direct_roundtrip_and_tampers() {
        for profile in [PcsProfile::Fast, PcsProfile::FixedCapacity] {
            const K_SKIP: usize = 2;
            let log_length = 8usize;
            let mut rng = Rng::new(0xC1_0F1E1D);
            let witness = (0..1usize << log_length)
                .map(|_| rng.f128())
                .collect::<Vec<_>>();
            let make_claim = |rng: &mut Rng| {
                let z_skip = rng.f256();
                let x_rest = (0..log_length - K_SKIP)
                    .map(|_| rng.f256())
                    .collect::<Vec<_>>();
                let value = zhat_quirky_reference_c1(&witness, K_SKIP, z_skip, &x_rest);
                C1QuirkyDirectClaim {
                    z_skip,
                    k_skip: K_SKIP,
                    x_rest,
                    value,
                }
            };
            let claims = vec![make_claim(&mut rng), make_claim(&mut rng)];
            let params = PcsParams {
                m: log_length + LOG_PACKING,
                log_inv_rate: 2,
                log_batch_size: 2,
                profile,
            };
            let (commitment, prover_data) = commit(&witness, &params);

            let mut prover = FsLaneChallenger::new_c1(b"history-c1-pcs-test");
            let proof = open_batch_quirky_direct_c1(
                &witness,
                &prover_data,
                &commitment,
                &claims,
                &mut prover,
            );
            let refs = claims
                .iter()
                .map(|claim| C1QuirkyDirectClaimRef {
                    z_skip: claim.z_skip,
                    k_skip: claim.k_skip,
                    x_rest: &claim.x_rest,
                    value: claim.value,
                })
                .collect::<Vec<_>>();
            let mut verifier = FsLaneChallenger::new_c1(b"history-c1-pcs-test");
            verify_opening_batch_quirky_direct_c1(&commitment, &refs, &proof, &mut verifier)
                .unwrap_or_else(|error| panic!("honest C1 quirky batch rejected: {error:?}"));
            assert_eq!(prover.sample_f256(), verifier.sample_f256());

            let mut wrong_profile = commitment.clone();
            wrong_profile.params.profile = if profile == PcsProfile::Fast {
                PcsProfile::FixedCapacity
            } else {
                PcsProfile::Fast
            };
            let mut verifier = FsLaneChallenger::new_c1(b"history-c1-pcs-test");
            assert!(
                verify_opening_batch_quirky_direct_c1(&wrong_profile, &refs, &proof, &mut verifier)
                    .is_err()
            );

            let mut wrong_claim = refs.clone();
            wrong_claim[0].value += F256::ONE;
            let mut verifier = FsLaneChallenger::new_c1(b"history-c1-pcs-test");
            assert!(
                verify_opening_batch_quirky_direct_c1(
                    &commitment,
                    &wrong_claim,
                    &proof,
                    &mut verifier,
                )
                .is_err()
            );

            let mut truncated = proof;
            truncated.queries.truncate(1);
            let mut verifier = FsLaneChallenger::new_c1(b"history-c1-pcs-test");
            assert!(
                verify_opening_batch_quirky_direct_c1(
                    &commitment,
                    &refs,
                    &truncated,
                    &mut verifier,
                )
                .is_err()
            );
        }
    }
}
