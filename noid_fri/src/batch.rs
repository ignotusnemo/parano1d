// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Linear-combination helpers for polynomial evaluations and codewords.
//!
//! Caller-supplied weights combine field elements, codewords and symbol pairs.

use noid_core::{Block128, TowerField};

/// Horner weights `λ_i = α^i` for `i = 0, …, n - 1`.
///
/// For `n > 0` and a fixed nonzero polynomial of degree at most `n - 1`,
/// evaluation at a uniformly sampled field element is zero with probability
/// at most `(n - 1) / |F|`.
pub fn horner_weights(alpha: Block128, n: usize) -> Vec<Block128> {
    let mut out = Vec::with_capacity(n);
    let mut cur = Block128::ONE;
    for _ in 0..n {
        out.push(cur);
        cur *= alpha;
    }
    out
}

/// Batched claim `e_batch = Σ λ_i · e_i`.
///
/// Panics if `lambdas.len() != openings.len()`.
pub fn rlc_openings(lambdas: &[Block128], openings: &[Block128]) -> Block128 {
    assert_eq!(
        lambdas.len(),
        openings.len(),
        "rlc_openings: lambda / opening length mismatch"
    );
    let mut acc = Block128::ZERO;
    for (&l, &e) in lambdas.iter().zip(openings.iter()) {
        acc += l * e;
    }
    acc
}

/// Pointwise batched codeword `C_batch[j] = Σ λ_i · C_i[j]`.
///
/// All inputs must be the same length. Column-major accumulation for
/// cache locality: each codeword is read sequentially, the output buffer
/// is written sequentially. Parallelised via fold/reduce over columns.
pub fn rlc_codewords(lambdas: &[Block128], codewords: &[&[Block128]]) -> Vec<Block128> {
    assert_eq!(
        lambdas.len(),
        codewords.len(),
        "rlc_codewords: lambda / codeword count mismatch"
    );
    assert!(
        !codewords.is_empty(),
        "rlc_codewords: need at least one codeword"
    );
    let len = codewords[0].len();
    for (i, cw) in codewords.iter().enumerate() {
        assert_eq!(
            cw.len(),
            len,
            "rlc_codewords: codeword {i} has length {} but expected {}",
            cw.len(),
            len
        );
    }

    use rayon::prelude::*;
    let n_cols = lambdas.len();
    (0..n_cols)
        .into_par_iter()
        .fold(
            || vec![Block128::ZERO; len],
            |mut acc, i| {
                let lam = lambdas[i];
                let cw = codewords[i];
                for j in 0..len {
                    acc[j] += lam * cw[j];
                }
                acc
            },
        )
        .reduce(
            || vec![Block128::ZERO; len],
            |mut a, b| {
                for j in 0..len {
                    a[j] += b[j];
                }
                a
            },
        )
}

/// Weighted symbol pair `(Σ λ_i · s_{i,0}, Σ λ_i · s_{i,1})`.
pub fn rlc_symbol_pairs(
    lambdas: &[Block128],
    pairs: &[(Block128, Block128)],
) -> (Block128, Block128) {
    assert_eq!(
        lambdas.len(),
        pairs.len(),
        "rlc_symbol_pairs: lambda / pair count mismatch"
    );
    let mut s0 = Block128::ZERO;
    let mut s1 = Block128::ZERO;
    for (&lam, &(a, b)) in lambdas.iter().zip(pairs.iter()) {
        s0 += lam * a;
        s1 += lam * b;
    }
    (s0, s1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0123_4567_89AB_CDEF)
    }

    fn rand_block(r: &mut StdRng) -> Block128 {
        Block128::from(r.gen::<u128>())
    }

    #[test]
    fn horner_weights_start_with_one_and_chain_correctly() {
        let mut r = rng();
        let alpha = rand_block(&mut r);
        let w = horner_weights(alpha, 6);
        assert_eq!(w.len(), 6);
        assert_eq!(w[0], Block128::ONE);
        for i in 1..6 {
            assert_eq!(w[i], w[i - 1] * alpha);
        }
    }

    #[test]
    fn horner_weights_zero_length() {
        let mut r = rng();
        let alpha = rand_block(&mut r);
        assert!(horner_weights(alpha, 0).is_empty());
    }

    #[test]
    fn rlc_openings_is_linear() {
        // Property: e_batch(λ, e) is linear in e for fixed λ.
        // e_batch(λ, e + e') == e_batch(λ, e) + e_batch(λ, e')
        let mut r = rng();
        let lambdas: Vec<Block128> = (0..5).map(|_| rand_block(&mut r)).collect();
        let e1: Vec<Block128> = (0..5).map(|_| rand_block(&mut r)).collect();
        let e2: Vec<Block128> = (0..5).map(|_| rand_block(&mut r)).collect();
        let e_sum: Vec<Block128> = e1.iter().zip(&e2).map(|(a, b)| *a + *b).collect();
        let lhs = rlc_openings(&lambdas, &e_sum);
        let rhs = rlc_openings(&lambdas, &e1) + rlc_openings(&lambdas, &e2);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn rlc_codewords_matches_per_position_rlc() {
        let mut r = rng();
        let n_cols = 4;
        let len = 32;
        let cws: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let lambdas: Vec<Block128> = (0..n_cols).map(|_| rand_block(&mut r)).collect();

        let cw_refs: Vec<&[Block128]> = cws.iter().map(|v| v.as_slice()).collect();
        let batched = rlc_codewords(&lambdas, &cw_refs);

        for j in 0..len {
            let mut expected = Block128::ZERO;
            for (i, lam) in lambdas.iter().enumerate() {
                expected += *lam * cws[i][j];
            }
            assert_eq!(batched[j], expected, "mismatch at position {j}");
        }
    }

    #[test]
    fn rlc_codewords_matches_scalar_reference() {
        // Compare the parallel accumulation with an independent scalar sum.
        let mut r = rng();
        let n_cols = 3;
        let len = 2048;
        let cws: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let lambdas: Vec<Block128> = (0..n_cols).map(|_| rand_block(&mut r)).collect();

        let cw_refs: Vec<&[Block128]> = cws.iter().map(|v| v.as_slice()).collect();
        let batched_parallel = rlc_codewords(&lambdas, &cw_refs);

        // Recompute via the scalar reference.
        let mut expected = vec![Block128::ZERO; len];
        for (i, lam) in lambdas.iter().enumerate() {
            for (j, v) in cws[i].iter().enumerate() {
                expected[j] += *lam * *v;
            }
        }
        assert_eq!(batched_parallel, expected);
    }

    #[test]
    fn rlc_symbol_pairs_is_linear_on_each_side() {
        let mut r = rng();
        let lambdas = horner_weights(rand_block(&mut r), 5);
        let pairs: Vec<(Block128, Block128)> = (0..5)
            .map(|_| (rand_block(&mut r), rand_block(&mut r)))
            .collect();
        let (s0, s1) = rlc_symbol_pairs(&lambdas, &pairs);

        // Reference via explicit loop.
        let mut r0 = Block128::ZERO;
        let mut r1 = Block128::ZERO;
        for (i, &(a, b)) in pairs.iter().enumerate() {
            r0 += lambdas[i] * a;
            r1 += lambdas[i] * b;
        }
        assert_eq!(s0, r0);
        assert_eq!(s1, r1);
    }

    /// Perturbing one entry changes the weighted sum by that entry's
    /// weight multiplied by the perturbation.
    #[test]
    fn rlc_openings_soundness_identity() {
        let mut r = rng();
        let lambdas = horner_weights(rand_block(&mut r), 4);
        let good: Vec<Block128> = (0..4).map(|_| rand_block(&mut r)).collect();
        let mut bad = good.clone();
        // Perturb column 2 — the only δ ≠ 0 is at index 2.
        bad[2] += Block128::ONE;

        let e_good = rlc_openings(&lambdas, &good);
        let e_bad = rlc_openings(&lambdas, &bad);
        // δ_i is all-zero except δ_2 = (good - bad) = ONE.
        let expected_diff = lambdas[2] * Block128::ONE;
        assert_eq!(e_good + e_bad, expected_diff);
    }
}
