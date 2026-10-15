// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! GF(2^256), the quadratic extension of the anchor GF(2^128) tower field.
//!
//! Elements are `lo + hi * X`, where
//!
//! ```text
//! X^2 + X + Block128::TAU = 0.
//! ```
//!
//! The 32-byte canonical encoding is the little-endian canonical encoding of
//! `lo`, followed by the encoding of `hi`.  In particular, the embedded
//! GF(2^128) subfield consists exactly of encodings whose final 16 bytes are
//! zero.

use crate::{
    Bit, Block128, Block16, Block32, Block64, Block8, CanonicalDeserialize, CanonicalSerialize,
    SerializationError, TowerField,
};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use zeroize::Zeroize;

/// One element of GF(2^256), represented by two GF(2^128) tower coordinates.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(C)]
pub struct Block256 {
    pub lo: Block128,
    pub hi: Block128,
}

impl Block256 {
    /// Constant for a possible next quadratic extension.  It follows the
    /// established tower convention: embed the previous level's extension
    /// constant in the high coordinate.
    pub const TAU: Self = Self {
        lo: Block128::ZERO,
        hi: Block128::TAU,
    };

    #[inline(always)]
    pub const fn new(lo: Block128, hi: Block128) -> Self {
        Self { lo, hi }
    }

    #[inline(always)]
    pub const fn split(self) -> (Block128, Block128) {
        (self.lo, self.hi)
    }

    /// Embed one GF(2^128) element into the distinguished base subfield.
    #[inline(always)]
    pub const fn from_base(value: Block128) -> Self {
        Self {
            lo: value,
            hi: Block128::ZERO,
        }
    }

    /// True exactly for the distinguished embedded GF(2^128) subfield.
    #[inline(always)]
    pub const fn is_in_base_subfield(self) -> bool {
        self.hi.0 == 0
    }

    /// Frobenius squaring in the quadratic extension.
    #[inline(always)]
    pub fn square(self) -> Self {
        let lo2 = self.lo.square();
        let hi2 = self.hi.square();
        Self {
            lo: lo2 + hi2 * Block128::TAU,
            hi: hi2,
        }
    }

    /// C1 challenge map from two uniform Poseidon2b rate lanes.
    ///
    /// `y^2 + y + tau` has absolute trace one, so the high coordinate is
    /// never zero. The map is exactly two-to-one in `y`; together with the
    /// independent low lane this yields exactly 255 bits of min-entropy and
    /// excludes the embedded GF(2^128) subfield without rejection sampling.
    #[inline(always)]
    pub fn from_raw_challenge_lanes(lo: Block128, raw_hi: Block128) -> Self {
        Self {
            lo,
            hi: raw_hi.square() + raw_hi + Block128::TAU,
        }
    }
}

impl TowerField for Block256 {
    const BITS: usize = 256;
    const ZERO: Self = Self {
        lo: Block128::ZERO,
        hi: Block128::ZERO,
    };
    const ONE: Self = Self {
        lo: Block128::ONE,
        hi: Block128::ZERO,
    };
    const EXTENSION_TAU: Self = Self::TAU;

    fn invert(&self) -> Self {
        let lo2 = self.lo.square();
        let hi2 = self.hi.square();
        let hi_lo = self.hi * self.lo;
        let norm = hi2 * Block128::TAU + hi_lo + lo2;
        let norm_inv = norm.invert();
        Self {
            lo: (self.hi + self.lo) * norm_inv,
            hi: self.hi * norm_inv,
        }
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&bytes[..16]);
        hi.copy_from_slice(&bytes[16..]);
        Self {
            lo: Block128(u128::from_le_bytes(lo)),
            hi: Block128(u128::from_le_bytes(hi)),
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for Block256 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self {
            lo: self.lo + rhs.lo,
            hi: self.hi + rhs.hi,
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for Block256 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl Mul for Block256 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        let v0 = self.lo * rhs.lo;
        let v1 = self.hi * rhs.hi;
        let v_sum = (self.lo + self.hi) * (rhs.lo + rhs.hi);
        Self {
            lo: v0 + v1 * Block128::TAU,
            hi: v0 + v_sum,
        }
    }
}

impl AddAssign for Block256 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for Block256 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for Block256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Block256 {
    fn serialized_size(&self) -> usize {
        32
    }

    fn serialize(&self, writer: &mut [u8]) -> Result<(), SerializationError> {
        if writer.len() < 32 {
            return Err(SerializationError);
        }
        CanonicalSerialize::serialize(&self.lo, &mut writer[..16])?;
        CanonicalSerialize::serialize(&self.hi, &mut writer[16..32])?;
        Ok(())
    }
}

impl CanonicalDeserialize for Block256 {
    fn deserialize(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() < 32 {
            return Err(SerializationError);
        }
        Ok(Self {
            lo: <Block128 as CanonicalDeserialize>::deserialize(&bytes[..16])?,
            hi: <Block128 as CanonicalDeserialize>::deserialize(&bytes[16..32])?,
        })
    }
}

impl From<u8> for Block256 {
    fn from(value: u8) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<u32> for Block256 {
    fn from(value: u32) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<u64> for Block256 {
    fn from(value: u64) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<u128> for Block256 {
    fn from(value: u128) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<Bit> for Block256 {
    fn from(value: Bit) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<Block8> for Block256 {
    fn from(value: Block8) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<Block16> for Block256 {
    fn from(value: Block16) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<Block32> for Block256 {
    fn from(value: Block32) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<Block64> for Block256 {
    fn from(value: Block64) -> Self {
        Self::from_base(Block128::from(value))
    }
}

impl From<Block128> for Block256 {
    fn from(value: Block128) -> Self {
        Self::from_base(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct TestRng(u64);

    impl TestRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn next_f128(&mut self) -> Block128 {
            Block128((self.next_u64() as u128) | ((self.next_u64() as u128) << 64))
        }

        fn next_f256(&mut self) -> Block256 {
            Block256::new(self.next_f128(), self.next_f128())
        }
    }

    fn absolute_trace(mut value: Block128) -> Block128 {
        let mut trace = value;
        for _ in 1..128 {
            value = value.square();
            trace += value;
        }
        trace
    }

    #[test]
    fn extension_polynomial_is_irreducible() {
        assert_eq!(absolute_trace(Block128::TAU), Block128::ONE);
        let x = Block256::new(Block128::ZERO, Block128::ONE);
        assert_eq!(
            x.square() + x + Block256::from(Block128::TAU),
            Block256::ZERO
        );
    }

    #[test]
    fn square_matches_multiplication() {
        let mut rng = TestRng(0xC1_0256);
        for _ in 0..256 {
            let value = rng.next_f256();
            assert_eq!(value.square(), value * value);
        }
    }

    #[test]
    fn field_axioms_and_inversion() {
        let mut rng = TestRng(0xC1_A11CE);
        for _ in 0..256 {
            let a = rng.next_f256();
            let b = rng.next_f256();
            let c = rng.next_f256();
            assert_eq!(a * (b + c), a * b + a * c);
            assert_eq!(a * b, b * a);
            assert_eq!((a * b) * c, a * (b * c));
            if a == Block256::ZERO {
                assert_eq!(a.invert(), Block256::ZERO);
            } else {
                assert_eq!(a * a.invert(), Block256::ONE);
            }
        }
    }

    #[test]
    fn embedding_is_a_field_homomorphism() {
        let mut rng = TestRng(0xC1_EBED);
        for _ in 0..256 {
            let a = rng.next_f128();
            let b = rng.next_f128();
            assert_eq!(Block256::from(a + b), Block256::from(a) + Block256::from(b));
            assert_eq!(Block256::from(a * b), Block256::from(a) * Block256::from(b));
        }
    }

    #[test]
    fn canonical_encoding_is_low_then_high() {
        let value = Block256::new(
            Block128(0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF),
            Block128(0xFFEE_DDCC_BBAA_9988_7766_5544_3322_1100),
        );
        let encoded = value.to_bytes();
        assert_eq!(&encoded[..16], &value.lo.0.to_le_bytes());
        assert_eq!(&encoded[16..], &value.hi.0.to_le_bytes());
        assert_eq!(
            <Block256 as CanonicalDeserialize>::deserialize(&encoded).unwrap(),
            value
        );
        assert!(<Block256 as CanonicalDeserialize>::deserialize(&encoded[..31]).is_err());
    }

    #[test]
    fn c1_sampler_excludes_base_subfield_and_is_two_to_one() {
        let mut rng = TestRng(0xC1_5A4D);
        for _ in 0..4096 {
            let lo = rng.next_f128();
            let y = rng.next_f128();
            let challenge = Block256::from_raw_challenge_lanes(lo, y);
            assert!(!challenge.is_in_base_subfield());
            assert_eq!(absolute_trace(challenge.hi), Block128::ONE);
            assert_eq!(
                challenge,
                Block256::from_raw_challenge_lanes(lo, y + Block128::ONE)
            );
        }
    }
}
