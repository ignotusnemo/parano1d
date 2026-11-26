//! C1 zerocheck for the F128-valued History relation.
//!
//! The committed relation and witness remain over GF(2^128).  Every
//! Fiat-Shamir challenge, prover message, running claim, and output claim in
//! this protocol lives in the quadratic extension GF(2^256).  Base-valued
//! inputs are scaled coordinate-wise whenever possible so the prover avoids
//! unnecessary full extension multiplications.

use crate::challenger::Challenger;
use crate::field::{F128, F256, PHI_8_TABLE};
use crate::zerocheck::field::SkipExtender;
use crate::zerocheck::{K_SKIP, VerifyError};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C1ZerocheckClaim {
    pub z: F256,
    pub mlv_challenges: Vec<F256>,
    pub r_rest: Vec<F256>,
    pub a_eval: F256,
    pub b_eval: F256,
    pub c_eval: F256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C1ZerocheckProof {
    pub round1_ab: Vec<F256>,
    pub round1_c: Vec<F256>,
    pub multilinear_rounds: Vec<(F256, F256)>,
    pub final_a_eval: F256,
    pub final_b_eval: F256,
    pub final_c_eval: F256,
}

pub(crate) fn build_eq_table(point: &[F256]) -> Vec<F256> {
    let mut out = Vec::with_capacity(1usize << point.len());
    out.push(F256::ONE);
    for (index, &challenge) in point.iter().enumerate() {
        let len = 1usize << index;
        out.resize(2 * len, F256::ZERO);
        let (low, high) = out.split_at_mut(len);
        if len >= 4096 {
            low.par_iter_mut()
                .zip(high.par_iter_mut())
                .for_each(|(low, high)| {
                    let value = *low;
                    *high = value * challenge;
                    *low = value + *high;
                });
        } else {
            for (low, high) in low.iter_mut().zip(high.iter_mut()) {
                let value = *low;
                *high = value * challenge;
                *low = value + *high;
            }
        }
    }
    out
}

pub(crate) fn lagrange_weights(k_skip: usize, z: F256, node_offset: usize) -> Vec<F256> {
    let count = 1usize << k_skip;
    assert!(node_offset + count <= PHI_8_TABLE.len());
    (0..count)
        .map(|i| {
            let node_i = PHI_8_TABLE[node_offset + i];
            let mut numerator = F256::ONE;
            let mut denominator = F128::ONE;
            for j in 0..count {
                if i == j {
                    continue;
                }
                let node_j = PHI_8_TABLE[node_offset + j];
                numerator *= z + F256::from_base(node_j);
                denominator *= node_i + node_j;
            }
            numerator.scale_base(denominator.inv())
        })
        .collect()
}

fn interpolate_on_lambda(values: &[F256], k_skip: usize, z: F256) -> F256 {
    let count = 1usize << k_skip;
    assert_eq!(values.len(), count);
    lagrange_weights(k_skip, z, count)
        .into_iter()
        .zip(values)
        .fold(F256::ZERO, |sum, (weight, &value)| sum + weight * value)
}

fn interpolate_combined(values_on_lambda: &[F256], k_skip: usize, z: F256) -> F256 {
    let count = 1usize << k_skip;
    assert_eq!(values_on_lambda.len(), count);
    assert!(2 * count <= PHI_8_TABLE.len());
    (0..count).fold(F256::ZERO, |sum, i| {
        let node_index = count + i;
        let node_i = PHI_8_TABLE[node_index];
        let mut numerator = F256::ONE;
        let mut denominator = F128::ONE;
        for (j, &node_j) in PHI_8_TABLE[..2 * count].iter().enumerate() {
            if j == node_index {
                continue;
            }
            numerator *= z + F256::from_base(node_j);
            denominator *= node_i + node_j;
        }
        sum + numerator.scale_base(denominator.inv()) * values_on_lambda[i]
    })
}

fn extend_s_to_lambda(extender: &SkipExtender, values: &mut [F256]) {
    let mut low = values.iter().map(|value| value.lo).collect::<Vec<_>>();
    let mut high = values.iter().map(|value| value.hi).collect::<Vec<_>>();
    extender.extend_s_to_lambda(&mut low);
    extender.extend_s_to_lambda(&mut high);
    for ((value, low), high) in values.iter_mut().zip(low).zip(high) {
        *value = F256::new(low, high);
    }
}

fn fold_pair(a: &mut Vec<F256>, b: &mut Vec<F256>, challenge: F256) {
    let length = a.len();
    assert_eq!(b.len(), length);
    assert!(length.is_power_of_two() && length >= 2);
    let half = length / 2;
    let mut next_a = Vec::with_capacity(half);
    let mut next_b = Vec::with_capacity(half);
    a.par_chunks_exact(2)
        .zip(b.par_chunks_exact(2))
        .map(|(a_pair, b_pair)| {
            (
                a_pair[0] + challenge * (a_pair[1] + a_pair[0]),
                b_pair[0] + challenge * (b_pair[1] + b_pair[0]),
            )
        })
        .unzip_into_vecs(&mut next_a, &mut next_b);
    // Write the two half-sized outputs directly in parallel. A temporary
    // tuple vector requires a serial copy and retains the original buffers.
    *a = next_a;
    *b = next_b;
}

fn round_pair(a: &[F256], b: &[F256], eq_challenges: &[F256]) -> (F256, F256) {
    assert_eq!(a.len(), b.len());
    assert!(a.len().is_power_of_two() && a.len() >= 2);
    assert_eq!(eq_challenges.len(), a.len().trailing_zeros() as usize);
    let eq_remaining = build_eq_table(&eq_challenges[1..]);
    let (g_one, g_infinity) = (0..a.len() / 2)
        .into_par_iter()
        .map(|index| {
            let a_zero = a[2 * index];
            let a_one = a[2 * index + 1];
            let b_zero = b[2 * index];
            let b_one = b[2 * index + 1];
            let weight = eq_remaining[index];
            (
                weight * a_one * b_one,
                weight * (a_zero + a_one) * (b_zero + b_one),
            )
        })
        .reduce(
            || (F256::ZERO, F256::ZERO),
            |left, right| (left.0 + right.0, left.1 + right.1),
        );
    (eq_challenges[0] * g_one, g_infinity)
}

pub fn prove<C: Challenger>(
    a: &[F128],
    b: &[F128],
    c: &[F128],
    m: usize,
    challenger: &mut C,
) -> (C1ZerocheckProof, C1ZerocheckClaim) {
    prove_with_fold(a, b, c, m, challenger, fold_pair)
}

// The injected folding operation lets tests compare the complete transcript
// against the previous implementation. Production uses only `fold_pair`.
fn prove_with_fold<C: Challenger>(
    a: &[F128],
    b: &[F128],
    c: &[F128],
    m: usize,
    challenger: &mut C,
    mut fold: impl FnMut(&mut Vec<F256>, &mut Vec<F256>, F256),
) -> (C1ZerocheckProof, C1ZerocheckClaim) {
    let k_skip = K_SKIP;
    let skip_size = 1usize << k_skip;
    assert!(m >= k_skip + 1, "prove requires m >= K_SKIP + 1");
    let length = 1usize << m;
    assert_eq!(a.len(), length);
    assert_eq!(b.len(), length);
    assert_eq!(c.len(), length);
    let mlv_rounds = m - k_skip;
    let rest_size = 1usize << mlv_rounds;

    challenger.observe_label(b"history-field-zerocheck-c1");
    let r_rest = challenger.sample_f256_vec(mlv_rounds);
    let eq = build_eq_table(&r_rest);

    let extender = SkipExtender::new(k_skip);
    let chunk = 1usize.max(rest_size / (8 * rayon::current_num_threads().max(1)));
    let (round1_ab, mut round1_c) = (0..rest_size.div_ceil(chunk))
        .into_par_iter()
        .map(|chunk_index| {
            let start = chunk_index * chunk;
            let end = ((chunk_index + 1) * chunk).min(rest_size);
            let mut ab_accumulator = vec![F256::ZERO; skip_size];
            let mut c_accumulator = vec![F256::ZERO; skip_size];
            let mut a_local = vec![F128::ZERO; skip_size];
            let mut b_local = vec![F128::ZERO; skip_size];
            for rest_index in start..end {
                let base = rest_index * skip_size;
                let weight = eq[rest_index];
                a_local.copy_from_slice(&a[base..base + skip_size]);
                b_local.copy_from_slice(&b[base..base + skip_size]);
                extender.extend_s_to_lambda(&mut a_local);
                extender.extend_s_to_lambda(&mut b_local);
                for skip_index in 0..skip_size {
                    ab_accumulator[skip_index] +=
                        weight.scale_base(a_local[skip_index] * b_local[skip_index]);
                    c_accumulator[skip_index] += weight.scale_base(c[base + skip_index]);
                }
            }
            (ab_accumulator, c_accumulator)
        })
        .reduce(
            || (vec![F256::ZERO; skip_size], vec![F256::ZERO; skip_size]),
            |(mut ab_left, mut c_left), (ab_right, c_right)| {
                for index in 0..skip_size {
                    ab_left[index] += ab_right[index];
                    c_left[index] += c_right[index];
                }
                (ab_left, c_left)
            },
        );
    extend_s_to_lambda(&extender, &mut round1_c);

    challenger.observe_f256_slice(&round1_ab);
    challenger.observe_f256_slice(&round1_c);
    let z = challenger.sample_f256();
    let final_c_eval = interpolate_on_lambda(&round1_c, k_skip, z);

    let skip_weights = lagrange_weights(k_skip, z, 0);
    let fold_at_z = |values: &[F128]| -> Vec<F256> {
        (0..rest_size)
            .into_par_iter()
            .map(|rest_index| {
                let base = rest_index * skip_size;
                (0..skip_size).fold(F256::ZERO, |sum, skip_index| {
                    sum + skip_weights[skip_index].scale_base(values[base + skip_index])
                })
            })
            .collect()
    };
    let mut a_mlv = fold_at_z(a);
    let mut b_mlv = fold_at_z(b);

    let mut multilinear_rounds = Vec::with_capacity(mlv_rounds);
    let mut mlv_challenges = Vec::with_capacity(mlv_rounds);
    {
        let mut next_eq = vec![F256::ONE; mlv_rounds];
        next_eq[1..].copy_from_slice(&r_rest[1..]);
        let message = round_pair(&a_mlv, &b_mlv, &next_eq);
        multilinear_rounds.push(message);
        challenger.observe_f256(message.0);
        challenger.observe_f256(message.1);
        mlv_challenges.push(challenger.sample_f256());
    }
    for round in 0..mlv_rounds - 1 {
        fold(&mut a_mlv, &mut b_mlv, mlv_challenges[round]);
        let log_length = a_mlv.len().trailing_zeros() as usize;
        let mut next_eq = vec![F256::ONE; log_length];
        next_eq[1..].copy_from_slice(&r_rest[round + 2..]);
        let message = round_pair(&a_mlv, &b_mlv, &next_eq);
        multilinear_rounds.push(message);
        challenger.observe_f256(message.0);
        challenger.observe_f256(message.1);
        mlv_challenges.push(challenger.sample_f256());
    }

    fold(
        &mut a_mlv,
        &mut b_mlv,
        *mlv_challenges.last().expect("at least one challenge"),
    );
    let final_a_eval = a_mlv[0];
    let final_b_eval = b_mlv[0];
    challenger.observe_f256(final_a_eval);
    challenger.observe_f256(final_b_eval);

    let proof = C1ZerocheckProof {
        round1_ab,
        round1_c,
        multilinear_rounds,
        final_a_eval,
        final_b_eval,
        final_c_eval,
    };
    let claim = C1ZerocheckClaim {
        z,
        mlv_challenges,
        r_rest,
        a_eval: final_a_eval,
        b_eval: final_b_eval,
        c_eval: final_c_eval,
    };
    (proof, claim)
}

pub fn verify<C: Challenger>(
    m: usize,
    proof: &C1ZerocheckProof,
    challenger: &mut C,
) -> Result<C1ZerocheckClaim, VerifyError> {
    let k_skip = K_SKIP;
    if m < k_skip + 1 {
        return Err(VerifyError::LogNTooSmall { log_n: m, k_skip });
    }
    let mlv_rounds = m - k_skip;
    let skip_size = 1usize << k_skip;
    if proof.round1_ab.len() != skip_size {
        return Err(VerifyError::BadRound1Length {
            expected: skip_size,
            got: proof.round1_ab.len(),
        });
    }
    if proof.round1_c.len() != skip_size {
        return Err(VerifyError::BadRound1Length {
            expected: skip_size,
            got: proof.round1_c.len(),
        });
    }
    if proof.multilinear_rounds.len() != mlv_rounds {
        return Err(VerifyError::BadMultilinearRoundsLength {
            expected: mlv_rounds,
            got: proof.multilinear_rounds.len(),
        });
    }

    challenger.observe_label(b"history-field-zerocheck-c1");
    let r_rest = challenger.sample_f256_vec(mlv_rounds);
    challenger.observe_f256_slice(&proof.round1_ab);
    challenger.observe_f256_slice(&proof.round1_c);
    let z = challenger.sample_f256();

    if interpolate_on_lambda(&proof.round1_c, k_skip, z) != proof.final_c_eval {
        return Err(VerifyError::CEvalMismatch);
    }
    let combined_at_lambda = proof
        .round1_ab
        .iter()
        .zip(&proof.round1_c)
        .map(|(&ab, &c)| ab + c)
        .collect::<Vec<_>>();
    let mut running = interpolate_combined(&combined_at_lambda, k_skip, z)
        + interpolate_on_lambda(&proof.round1_c, k_skip, z);

    let mut mlv_challenges = Vec::with_capacity(mlv_rounds);
    for (round, &(message_one, message_infinity)) in proof.multilinear_rounds.iter().enumerate() {
        let eq_challenge = r_rest[round];
        let one_plus_eq = F256::ONE + eq_challenge;
        let value_zero = (running + eq_challenge * message_one) * one_plus_eq.inv();

        challenger.observe_f256(message_one);
        challenger.observe_f256(message_infinity);
        let challenge = challenger.sample_f256();
        mlv_challenges.push(challenge);

        let one_plus_challenge = F256::ONE + challenge;
        running = value_zero * one_plus_challenge
            + message_one * challenge
            + message_infinity * challenge * one_plus_challenge;
    }

    if running != proof.final_a_eval * proof.final_b_eval {
        return Err(VerifyError::SumcheckFinalFailed);
    }
    challenger.observe_f256(proof.final_a_eval);
    challenger.observe_f256(proof.final_b_eval);

    Ok(C1ZerocheckClaim {
        z,
        mlv_challenges,
        r_rest,
        a_eval: proof.final_a_eval,
        b_eval: proof.final_b_eval,
        c_eval: proof.final_c_eval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::FsLaneChallenger;

    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            value ^ (value >> 31)
        }

        fn f128(&mut self) -> F128 {
            F128::new(self.next_u64(), self.next_u64())
        }

        fn f128_vec(&mut self, length: usize) -> Vec<F128> {
            (0..length).map(|_| self.f128()).collect()
        }
    }

    fn valid_instance(m: usize, seed: u64) -> (Vec<F128>, Vec<F128>, Vec<F128>) {
        let mut rng = Rng(seed);
        let a = rng.f128_vec(1usize << m);
        let b = rng.f128_vec(1usize << m);
        let c = a.iter().zip(&b).map(|(&x, &y)| x * y).collect();
        (a, b, c)
    }

    #[test]
    fn binary_equality_tables_match_the_two_product_reference() {
        let reference = |point: &[F256]| {
            let mut values = vec![F256::ONE];
            for &q in point {
                let count = values.len();
                let mut next = vec![F256::ZERO; 2 * count];
                for (i, &v) in values.iter().enumerate() {
                    next[i] = v * (F256::ONE + q);
                    next[count + i] = v * q;
                }
                values = next;
            }
            values
        };
        let mut rng = Rng(0xe0a1_17ab_1e);
        for log in 0..=16 {
            for boolean in [false, true] {
                let mut point: Vec<_> = (0..log)
                    .map(|_| F256::new(rng.f128(), rng.f128()))
                    .collect();
                if boolean && log != 0 {
                    point[0] = F256::ZERO;
                    point[log - 1] = F256::ONE;
                }
                assert_eq!(build_eq_table(&point), reference(&point));
                let base: Vec<_> = point.iter().map(|q| q.lo).collect();
                let lifted: Vec<_> = base.iter().copied().map(F256::from_base).collect();
                assert_eq!(
                    crate::lincheck::build_eq_table(&base),
                    reference(&lifted)
                        .into_iter()
                        .map(|q| q.lo)
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    // Reference from before the direct-output optimization. Keeping it in
    // tests permits full proof/transcript parity and interleaved A/B timings.
    fn fold_pair_reference(a: &mut Vec<F256>, b: &mut Vec<F256>, challenge: F256) {
        let length = a.len();
        assert_eq!(b.len(), length);
        assert!(length.is_power_of_two() && length >= 2);
        let half = length / 2;
        let folded = a
            .par_chunks_exact(2)
            .zip(b.par_chunks_exact(2))
            .map(|(a_pair, b_pair)| {
                (
                    a_pair[0] + challenge * (a_pair[1] + a_pair[0]),
                    b_pair[0] + challenge * (b_pair[1] + b_pair[0]),
                )
            })
            .collect::<Vec<_>>();
        a.truncate(half);
        b.truncate(half);
        for (index, (a_value, b_value)) in folded.into_iter().enumerate() {
            a[index] = a_value;
            b[index] = b_value;
        }
    }

    #[test]
    fn c1_direct_folding_preserves_reference_proof_and_transcript() {
        for m in [7, 8, 16] {
            let (a, b, c) = valid_instance(m, 0xC1F01D + m as u64);
            let run = |threads, reference| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap()
                    .install(|| {
                        let mut channel = FsLaneChallenger::new_c1(b"field-c1-direct-fold");
                        let (proof, claim) = if reference {
                            prove_with_fold(&a, &b, &c, m, &mut channel, fold_pair_reference)
                        } else {
                            prove(&a, &b, &c, m, &mut channel)
                        };
                        (proof, claim, channel.sample_f256())
                    })
            };
            let reference = run(1, true);
            for threads in [1, 4] {
                let actual = run(threads, false);
                assert_eq!(actual, reference, "m={m}, threads={threads}");
                assert_eq!(
                    bincode::serialize(&actual.0).unwrap(),
                    bincode::serialize(&reference.0).unwrap()
                );
                let mut verifier = FsLaneChallenger::new_c1(b"field-c1-direct-fold");
                assert_eq!(verify(m, &actual.0, &mut verifier).unwrap(), actual.1);
                assert_eq!(verifier.sample_f256(), actual.2);
            }
        }
    }

    #[test]
    fn c1_direct_folding_releases_previous_capacity() {
        let mut rng = Rng(0xC1CA9);
        let mut a: Vec<_> = (0..4096)
            .map(|_| F256::new(rng.f128(), rng.f128()))
            .collect();
        let mut b = a.iter().rev().copied().collect::<Vec<_>>();
        let (mut expected_a, mut expected_b) = (a.clone(), b.clone());
        let challenges = [F256::ZERO, F256::ONE, F256::new(rng.f128(), rng.f128())];
        let mut round = 0;
        while a.len() > 1 {
            let challenge = challenges[round % challenges.len()];
            fold_pair_reference(&mut expected_a, &mut expected_b, challenge);
            fold_pair(&mut a, &mut b, challenge);
            assert_eq!(a, expected_a);
            assert_eq!(b, expected_b);
            assert_eq!(a.capacity(), a.len());
            assert_eq!(b.capacity(), b.len());
            round += 1;
        }
    }

    #[test]
    #[ignore = "isolated production-width C1 zerocheck A/B measurement"]
    fn bench_c1_direct_folding() {
        use std::time::{Duration, Instant};
        let number = |name: &str, default: usize| {
            std::env::var(name)
                .map(|v| v.parse::<usize>().expect("numeric benchmark option"))
                .unwrap_or(default)
        };
        let m = number("NOID_C1_FOLD_BENCH_M", 23);
        let samples = number("NOID_C1_FOLD_BENCH_SAMPLES", 7);
        assert!((7..=24).contains(&m));
        assert!((1..=30).contains(&samples));
        let (a, b, c) = valid_instance(m, 0xC1F01D + m as u64);
        println!(
            "{}",
            serde_json::json!({
                "phase": "setup", "m": m, "samples": samples,
                "threads": rayon::current_num_threads(),
                "cpu_backend": noid_core::cpu::selected_backend().to_string(),
                "input_bytes": (a.len() + b.len() + c.len()) * std::mem::size_of::<F128>()
            })
        );
        let mut expected = None;
        // Sample zero warms both implementations; subsequent pairs alternate
        // order. This isolates folding, not full HistoryStep construction.
        for sample in 0..=samples {
            for reference in if sample % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let mut channel = FsLaneChallenger::new_c1(b"field-c1-direct-fold-bench");
                let mut fold_time = Duration::ZERO;
                let mut first_retained_bytes = None;
                let start = Instant::now();
                let (proof, claim) = prove_with_fold(&a, &b, &c, m, &mut channel, |a, b, r| {
                    let start = Instant::now();
                    if reference {
                        fold_pair_reference(a, b, r);
                    } else {
                        fold_pair(a, b, r);
                    }
                    fold_time += start.elapsed();
                    first_retained_bytes
                        .get_or_insert((a.capacity() + b.capacity()) * std::mem::size_of::<F256>());
                });
                let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
                let following = channel.sample_f256();
                let encoded = bincode::serialize(&(&proof, following)).unwrap();
                if let Some(expected) = &expected {
                    assert_eq!(&encoded, expected, "proof/transcript changed");
                } else {
                    expected = Some(encoded.clone());
                }
                let mut verifier = FsLaneChallenger::new_c1(b"field-c1-direct-fold-bench");
                let start = Instant::now();
                let verified = verify(m, &proof, &mut verifier).unwrap();
                let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(claim, verified);
                assert_eq!(following, verifier.sample_f256());
                println!(
                    "{}",
                    serde_json::json!({
                        "sample": sample, "warmup": sample == 0, "m": m,
                        "implementation": if reference { "reference" } else { "direct" },
                        "prove_ms": prove_ms, "fold_ms": fold_time.as_secs_f64() * 1000.0,
                        "verify_ms": verify_ms, "first_retained_bytes": first_retained_bytes,
                        "proof_and_following_bytes": encoded.len(), "parity": true
                    })
                );
            }
        }
    }

    #[test]
    fn c1_prove_verify_roundtrip_and_claims_are_wide() {
        for m in [7usize, 8, 10] {
            let (a, b, c) = valid_instance(m, 0xC100 + m as u64);
            let mut prover = FsLaneChallenger::new_c1(b"field-c1-zc-test");
            let (proof, prover_claim) = prove(&a, &b, &c, m, &mut prover);
            let mut verifier = FsLaneChallenger::new_c1(b"field-c1-zc-test");
            let verifier_claim = verify(m, &proof, &mut verifier)
                .unwrap_or_else(|error| panic!("C1 proof rejected at m={m}: {error:?}"));

            assert_eq!(prover_claim, verifier_claim);
            assert_eq!(proof.round1_ab.len(), 1usize << K_SKIP);
            assert_eq!(proof.multilinear_rounds.len(), m - K_SKIP);
            assert!(prover_claim.r_rest.iter().all(|value| !value.hi.is_zero()));
            assert!(
                prover_claim
                    .mlv_challenges
                    .iter()
                    .all(|value| !value.hi.is_zero())
            );
            assert_eq!(prover.sample_f256(), verifier.sample_f256());
        }
    }

    #[test]
    fn c1_final_evaluations_match_direct_extension_mle() {
        let m = 8;
        let (a, b, c) = valid_instance(m, 0xC1A11CE);
        let mut challenger = FsLaneChallenger::new_c1(b"field-c1-zc-eval");
        let (proof, claim) = prove(&a, &b, &c, m, &mut challenger);

        let evaluate = |values: &[F128], z: F256, rest: &[F256]| {
            let skip_weights = lagrange_weights(K_SKIP, z, 0);
            let rest_weights = build_eq_table(rest);
            values
                .iter()
                .enumerate()
                .fold(F256::ZERO, |sum, (index, &value)| {
                    sum + (skip_weights[index % (1usize << K_SKIP)] * rest_weights[index >> K_SKIP])
                        .scale_base(value)
                })
        };

        assert_eq!(
            evaluate(&a, claim.z, &claim.mlv_challenges),
            proof.final_a_eval
        );
        assert_eq!(
            evaluate(&b, claim.z, &claim.mlv_challenges),
            proof.final_b_eval
        );
        assert_eq!(evaluate(&c, claim.z, &claim.r_rest), proof.final_c_eval);
    }

    #[test]
    fn c1_false_statement_and_proof_mutations_are_rejected() {
        let m = 8;
        let (a, b, mut c) = valid_instance(m, 0xC1BAD);
        c[37] += F128::ONE;
        let mut cheating = FsLaneChallenger::new_c1(b"field-c1-zc-false");
        let (false_proof, _) = prove(&a, &b, &c, m, &mut cheating);
        let mut verifier = FsLaneChallenger::new_c1(b"field-c1-zc-false");
        assert!(verify(m, &false_proof, &mut verifier).is_err());

        let (a, b, c) = valid_instance(m, 0xC1BAD + 1);
        let mut prover = FsLaneChallenger::new_c1(b"field-c1-zc-mutate");
        let (proof, _) = prove(&a, &b, &c, m, &mut prover);
        let mutations: Vec<Box<dyn Fn(&mut C1ZerocheckProof)>> = vec![
            Box::new(|candidate| candidate.round1_ab[0].lo.lo ^= 1),
            Box::new(|candidate| candidate.round1_c[7].hi.hi ^= 1),
            Box::new(|candidate| candidate.multilinear_rounds[0].0.hi.lo ^= 1),
            Box::new(|candidate| candidate.final_a_eval.lo.hi ^= 1),
            Box::new(|candidate| candidate.final_b_eval.hi.lo ^= 1),
            Box::new(|candidate| candidate.final_c_eval.hi.hi ^= 1),
        ];
        for mutate in mutations {
            let mut candidate = proof.clone();
            mutate(&mut candidate);
            let mut verifier = FsLaneChallenger::new_c1(b"field-c1-zc-mutate");
            assert!(verify(m, &candidate, &mut verifier).is_err());
        }

        let mut truncated = proof;
        truncated.round1_ab.pop();
        let mut verifier = FsLaneChallenger::new_c1(b"field-c1-zc-mutate");
        assert!(matches!(
            verify(m, &truncated, &mut verifier),
            Err(VerifyError::BadRound1Length { .. })
        ));
    }
}
