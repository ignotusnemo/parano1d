// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! VPCLMULQDQ implementation of flat-basis GF(2^128) multiplication for
//! PACKED_LANES = 2.
//!
//! Multiplies both u128 lanes of a `PackedBlock128` in parallel inside a
//! single `__m256i`: four carry-less 64×64 products per lane (schoolbook —
//! Karatsuba would trade one CLMUL for two extra shuffles on the same
//! execution port) followed by a two-product Horner reduction by the tail
//! polynomial 0x87. The whole
//! multiply stays in the vector domain; the scalar path in
//! `hardware::clmul_gcm` instead crosses into general-purpose registers for
//! its shift-based reduction on every call.
//!
//! The module is only compiled when 256-bit VPCLMULQDQ is available and
//! AVX-512 is not — i.e. the PACKED_LANES == 2 configuration with the wide
//! carry-less multiply extension (Alder/Raptor Lake class cores).

#![cfg(target_arch = "x86_64")]

use super::PackedBlock128;
use core::arch::x86_64::*;

// NOTE: every function carries the SAME `#[target_feature]` set, so the
// `#[inline(always)]` fusion between them is preserved (rustc inlines across
// matching target_feature boundaries). The module is compiled on all
// x86_64 (except avx512f layout builds) and entered only through runtime
// `is_x86_feature_detected!` dispatch or a statically-enabled build.

/// Reduce two 256-bit carry-less products (per 128-bit lane: `hi:lo`)
/// modulo x^128 + x^7 + x^2 + x + 1.
///
/// Identical algebra to `hardware::reduce_gcm_256`. Fold the high 64-bit
/// word into the next word, then fold that word into the low half. This
/// computes the same remainder with two carry-less products instead of
/// the three-product decomposition.
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
pub unsafe fn reduce_gcm_x2(hi: __m256i, lo: __m256i) -> __m256i {
    let p = _mm256_set1_epi64x(0x87);
    let middle = _mm256_xor_si256(
        _mm256_bslli_epi128(hi, 8),
        _mm256_clmulepi64_epi128(hi, p, 0x01),
    );
    _mm256_xor_si256(
        lo,
        _mm256_xor_si256(
            _mm256_bslli_epi128(middle, 8),
            _mm256_clmulepi64_epi128(middle, p, 0x01),
        ),
    )
}

/// Two independent flat-basis GF(2^128) multiplications, one per 128-bit
/// lane of the 256-bit registers — the register-domain core shared by the
/// packed wrappers below and the vector permutation kernels.
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
pub unsafe fn mul_gcm_x2(a: __m256i, b: __m256i) -> __m256i {
    let t_ll = _mm256_clmulepi64_epi128(a, b, 0x00);
    let t_hh = _mm256_clmulepi64_epi128(a, b, 0x11);
    let t_lh = _mm256_clmulepi64_epi128(a, b, 0x10);
    let t_hl = _mm256_clmulepi64_epi128(a, b, 0x01);
    let mid = _mm256_xor_si256(t_lh, t_hl);
    let lo = _mm256_xor_si256(t_ll, _mm256_bslli_epi128(mid, 8));
    let hi = _mm256_xor_si256(t_hh, _mm256_bsrli_epi128(mid, 8));
    reduce_gcm_x2(hi, lo)
}

/// Two independent flat-basis squarings via the carry-less multiplier: in
/// characteristic 2 the cross terms of (lo + hi·x^64)² cancel, so the
/// 256-bit square is just `clmul(lo,lo) ‖ clmul(hi,hi)` — 4 CLMULs total
/// with the reduction, versus ~25 port-5 shuffle/shift µops for the
/// bit-spread square. Preferable when squares sit between multiplies (the
/// S-box), where the shuffle pressure on the CLMUL port is what hurts.
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
pub unsafe fn square_gcm_clmul_x2(a: __m256i) -> __m256i {
    let lo = _mm256_clmulepi64_epi128(a, a, 0x00);
    let hi = _mm256_clmulepi64_epi128(a, a, 0x11);
    reduce_gcm_x2(hi, lo)
}

#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn load(x: &PackedBlock128) -> __m256i {
    _mm256_loadu_si256(x as *const PackedBlock128 as *const __m256i)
}

#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn store(v: __m256i) -> PackedBlock128 {
    let mut out = core::mem::MaybeUninit::<PackedBlock128>::uninit();
    _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, v);
    out.assume_init()
}

/// Lane-parallel `clmul_gcm` of two packed flat-basis values.
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
pub unsafe fn packed_mul_flat_avx2(a: PackedBlock128, b: PackedBlock128) -> PackedBlock128 {
    store(mul_gcm_x2(load(&a), load(&b)))
}

/// Lane-parallel `clmul_gcm` of a packed flat-basis value by one flat
/// scalar (broadcast into both lanes).
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
pub unsafe fn packed_scalar_mul_flat_avx2(a: PackedBlock128, scalar_flat: u128) -> PackedBlock128 {
    let s = _mm256_broadcastsi128_si256(core::mem::transmute::<u128, __m128i>(scalar_flat));
    store(mul_gcm_x2(load(&a), s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::clmul_gcm;

    fn kernel_supported() -> bool {
        std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("vpclmulqdq")
    }

    fn rng(seed: &mut u64) -> u128 {
        let mut next = || {
            *seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = *seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        };
        ((next() as u128) << 64) | next() as u128
    }

    /// The vector multiply must be BIT-IDENTICAL to the scalar `clmul_gcm`
    /// on every lane — digest identity across the whole tree stack follows
    /// from this single equivalence.
    #[test]
    fn packed_mul_matches_scalar_clmul_gcm() {
        if !kernel_supported() {
            return;
        }
        let mut s = 0xB00B5EED_u64;
        for _ in 0..20_000 {
            let a = [rng(&mut s), rng(&mut s)];
            let b = [rng(&mut s), rng(&mut s)];
            let pa = PackedBlock128 { lanes: a };
            let pb = PackedBlock128 { lanes: b };
            let got = unsafe { packed_mul_flat_avx2(pa, pb) };
            for i in 0..2 {
                assert_eq!(got.lanes[i], clmul_gcm(a[i], b[i]), "lane {i}");
            }
        }
        // Edge patterns: zero, one, all-ones, single high/low bits.
        let edges = [0u128, 1, !0, 1 << 127, 1 << 64, (1 << 64) - 1, 0x87];
        for &x in &edges {
            for &y in &edges {
                let got = unsafe {
                    packed_mul_flat_avx2(
                        PackedBlock128 { lanes: [x, y] },
                        PackedBlock128 { lanes: [y, x] },
                    )
                };
                assert_eq!(got.lanes[0], clmul_gcm(x, y));
                assert_eq!(got.lanes[1], clmul_gcm(y, x));
            }
        }
    }

    #[test]
    fn packed_scalar_mul_matches_scalar_clmul_gcm() {
        if !kernel_supported() {
            return;
        }
        let mut s = 0x5CA1AB1E_u64;
        for _ in 0..10_000 {
            let a = [rng(&mut s), rng(&mut s)];
            let c = rng(&mut s);
            let got = unsafe { packed_scalar_mul_flat_avx2(PackedBlock128 { lanes: a }, c) };
            for i in 0..2 {
                assert_eq!(got.lanes[i], clmul_gcm(a[i], c), "lane {i}");
            }
        }
    }

    fn reduce_reference(mut hi: u128, mut lo: u128) -> u128 {
        // Polynomial long division, independent of both CLMUL reducers.
        for bit in (0..128).rev() {
            if (hi >> bit) & 1 == 0 {
                continue;
            }
            hi ^= 1u128 << bit;
            for tail in [0, 1, 2, 7] {
                let position = bit + tail;
                if position < 128 {
                    lo ^= 1u128 << position;
                } else {
                    hi ^= 1u128 << (position - 128);
                }
            }
        }
        assert_eq!(hi, 0);
        lo
    }

    #[test]
    fn horner_reduction_matches_independent_polynomial_division() {
        if !kernel_supported() {
            return;
        }
        let check = |hi: [u128; 2], lo: [u128; 2]| {
            let mut actual = [0u128; 2];
            unsafe {
                let vh = _mm256_loadu_si256(hi.as_ptr().cast());
                let vl = _mm256_loadu_si256(lo.as_ptr().cast());
                _mm256_storeu_si256(actual.as_mut_ptr().cast(), reduce_gcm_x2(vh, vl));
            }
            for lane in 0..2 {
                assert_eq!(actual[lane], reduce_reference(hi[lane], lo[lane]));
            }
        };
        check([0, !0], [0, !0]);
        for bit in 0..128 {
            check([1u128 << bit, 0], [0, 1u128 << bit]);
            check([0, 1u128 << bit], [1u128 << bit, 0]);
        }
        let mut seed = 0xa11d17;
        for _ in 0..20_000 {
            check(
                [rng(&mut seed), rng(&mut seed)],
                [rng(&mut seed), rng(&mut seed)],
            );
        }
    }
}
