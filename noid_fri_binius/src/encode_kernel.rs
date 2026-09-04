//! Closed-form encode kernel for the source-binding Reed-Solomon codeword.
//!
//! `Code::new_parallel(message)` is four cosets of the constant-twiddle
//! additive NTT (`noid_core::ntt::AdditiveNTT`): coset `c ∈ 0..4` is
//! `forward_transform(message, c)`, whose layer `l` applies the butterfly
//! `(u, v) → (u+v, (u+v)·b + v)` with the CONSTANT twiddle `b = 2^{c+l}`.
//! Because every twiddle is a per-layer constant, the whole transform is a
//! Kronecker product of the fixed 2×2 matrix `M(b) = [[1,1],[b,b+1]]` over
//! the position bits, so the codeword MLE has a closed form:
//!
//! ```text
//!   codeword~(z) = Σ_i K_i(z)·message[i]
//!   K_i(z) = Σ_{c=0}^{3} eq₂(z_hi; c) · Π_{l=0}^{L-1} [ 1 + z_l·(1 + i_l + 2^{c+l}) ]
//! ```
//!
//! with `L = n_rounds`, `z` = `n_rounds+2` coords (low `n_rounds` = position
//! bits, high 2 = coset bits, MLE LSB-first), `i_l` = bit `l` of the message
//! index, and `eq₂(z_hi; c)` the 2-bit equality selecting coset `c`. The
//! single-bit factor is `M(b)[p_l][i_l] = 1 + p_l·(1 + i_l + b)` (char 2:
//! `p_l=0 → 1`; `p_l=1 → b` for `i_l=0`, `b+1` for `i_l=1`).
//!
//! This is witness-free and costs `O(4·n_rounds)` field ops per evaluation —
//! the source binding's `codeword = Code(H·eq_right)` check reduces to ONE
//! sumcheck `codeword~(z) = Σ_i K_i(z)·g_evals[i]` over the `2^n_rounds`
//! message coefficients, no full-codeword materialization.

use noid_core::{Block128, TowerField};

/// The 2-bit equality polynomial `eq₂(z_hi; c) = Π_k [c_k ? z_hi_k : 1+z_hi_k]`.
fn eq2(z_hi: &[Block128], c: usize) -> Block128 {
    let mut e = Block128::ONE;
    for (k, &zk) in z_hi.iter().enumerate() {
        e *= if (c >> k) & 1 == 1 {
            zk
        } else {
            Block128::ONE + zk
        };
    }
    e
}

/// The kernel weight evaluated at a CONTINUOUS message point `x` (the
/// multilinear extension in the message coordinates): `K(z, x) = Σ_c
/// eq₂(z_hi;c)·Π_l [1 + z_l·(1 + x_l + 2^{c+l})]`. The per-bit factor is
/// affine in `x_l`, so this is the genuine MLE — used by the source-binding
/// sumcheck's terminal check at its derived point. `x.len() == n_rounds`.
pub fn encode_kernel_weight_at(z: &[Block128], x: &[Block128], n_rounds: usize) -> Block128 {
    assert_eq!(z.len(), n_rounds + 2, "encode kernel point arity");
    assert_eq!(x.len(), n_rounds, "message point arity");
    let z_pos = &z[..n_rounds];
    let z_hi = &z[n_rounds..];
    let mut total = Block128::ZERO;
    for c in 0..4usize {
        let mut prod = Block128::ONE;
        for (l, (&z_l, &x_l)) in z_pos.iter().zip(x.iter()).enumerate() {
            let two = Block128::from(1u128 << (c + l));
            // M(b)[·][x_l] extended: 1 + z_l·(1 + x_l + b)
            prod *= Block128::ONE + z_l * (Block128::ONE + x_l + two);
        }
        total += eq2(z_hi, c) * prod;
    }
    total
}

/// The single message-index kernel weight `K_i(z)` (see module docs). `z`
/// must have exactly `n_rounds + 2` coordinates.
pub fn encode_kernel_weight(z: &[Block128], i: usize, n_rounds: usize) -> Block128 {
    let x: Vec<Block128> = (0..n_rounds)
        .map(|l| {
            if (i >> l) & 1 == 1 {
                Block128::ONE
            } else {
                Block128::ZERO
            }
        })
        .collect();
    encode_kernel_weight_at(z, &x, n_rounds)
}

/// All `2^n_rounds` kernel weights at `z`, sharing the per-coset structure.
pub fn encode_kernel_weights(z: &[Block128], n_rounds: usize) -> Vec<Block128> {
    (0..(1usize << n_rounds))
        .map(|i| encode_kernel_weight(z, i, n_rounds))
        .collect()
}

/// `Σ_i K_i(z)·message[i]` — the closed-form codeword MLE at `z`.
pub fn encode_mle_via_kernel(message: &[Block128], z: &[Block128], n_rounds: usize) -> Block128 {
    assert_eq!(message.len(), 1usize << n_rounds, "message length");
    let mut acc = Block128::ZERO;
    for (i, &m) in message.iter().enumerate() {
        acc += encode_kernel_weight(z, i, n_rounds) * m;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::AdditiveNTT;
    use noid_fri::code::{Code, LOG_RATE};

    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn block(&mut self) -> Block128 {
            Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
        }
    }

    fn mle_eval(vals: &[Block128], z: &[Block128]) -> Block128 {
        // LSB-first: bit k of the index ↔ z[k].
        let mut acc = Block128::ZERO;
        for (idx, &v) in vals.iter().enumerate() {
            let mut e = Block128::ONE;
            for (k, &zk) in z.iter().enumerate() {
                e *= if (idx >> k) & 1 == 1 {
                    zk
                } else {
                    Block128::ONE + zk
                };
            }
            acc += v * e;
        }
        acc
    }

    /// The load-bearing fact for the in-region source binding: the closed-form
    /// encode kernel reproduces the MLE of the REAL `Code::new_parallel`
    /// codeword at a random point, across message sizes.
    #[test]
    fn encode_kernel_matches_code_new_parallel() {
        let mut rng = Rng(0xE0DE);
        for n_rounds in [1usize, 2, 3, 5, 7] {
            let ntt = AdditiveNTT::<Block128>::new(n_rounds + LOG_RATE);
            let message: Vec<Block128> = (0..(1usize << n_rounds)).map(|_| rng.block()).collect();
            let code = Code::new_parallel(&message, &ntt);
            assert_eq!(code.encoding.len(), message.len() * 4);

            // The codeword layout is [coset | position] with position in the
            // low n_rounds bits — matching the kernel's z_pos/z_hi split.
            let z: Vec<Block128> = (0..n_rounds + 2).map(|_| rng.block()).collect();
            let direct = mle_eval(&code.encoding, &z);
            let via_kernel = encode_mle_via_kernel(&message, &z, n_rounds);
            assert_eq!(direct, via_kernel, "kernel mismatch at n_rounds={n_rounds}");
        }
    }

    /// The kernel is genuinely multilinear in z (agrees with the codeword MLE
    /// at boolean points = the raw codeword symbols), sanity for the layout.
    #[test]
    fn encode_kernel_at_boolean_points_is_the_codeword() {
        let mut rng = Rng(0xB001);
        let n_rounds = 3usize;
        let ntt = AdditiveNTT::<Block128>::new(n_rounds + LOG_RATE);
        let message: Vec<Block128> = (0..(1usize << n_rounds)).map(|_| rng.block()).collect();
        let code = Code::new_parallel(&message, &ntt);
        for j in 0..code.encoding.len() {
            let z: Vec<Block128> = (0..n_rounds + 2)
                .map(|k| {
                    if (j >> k) & 1 == 1 {
                        Block128::ONE
                    } else {
                        Block128::ZERO
                    }
                })
                .collect();
            assert_eq!(
                encode_mle_via_kernel(&message, &z, n_rounds),
                code.encoding[j],
                "kernel != codeword[{j}]"
            );
        }
    }
}
