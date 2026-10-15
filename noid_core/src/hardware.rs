// SPDX-License-Identifier: Apache-2.0
// Ported from hekate-math. Copyright (C) 2026 Paranoid Zero.

//! `HardwareField` trait and `Flat<Block128>` isomorphic-basis wrapper.
//!
//! The *flat* basis enables carry-less multiply (CLMUL) hardware acceleration.
//! We convert from the tower basis into a standard polynomial basis modulo
//! x^128 + x^7 + x^2 + x + 1 (GCM polynomial), use CLMUL, and convert back.

use crate::Block128;
use crate::SerializationError;
use crate::TowerField;
use crate::{CanonicalDeserialize, CanonicalSerialize};
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use zeroize::Zeroize;

/// Marker trait for fields with a hardware-accelerated flat representation.
pub trait HardwareField: TowerField {
    fn to_flat(&self) -> Self;
    fn to_tower(&self) -> Self;
}

// ---------------------------------------------------------------------------
// Basis Conversion Matrices
// ---------------------------------------------------------------------------

mod conversion_matrix {
    /// Tower basis -> Standard GCM polynomial basis.
    pub const TOWER_TO_FLAT: [u128; 128] = [
        0x1,
        0x3d5bd35c94646a247573da4a5f7710ed,
        0xa72ec17764d7ced55e2f716f4ede412f,
        0x553e92e8bc0ae9a795ed1f57f3632d4d,
        0xc7bd33d0a58cf5b4740d6c968b842acb,
        0x486fb01f93aa169afd8ee716e990cf14,
        0xbee4e4dc44629cf627b537f28935c282,
        0x549810e11a88dea5252b49277b1b82b4,
        0x6198d3a7b756c056bd3d5a025c8d370a,
        0xb2ef6c31981e31582924ed9040490830,
        0x9ee93d00b6b040353ebf5c8e0d4401d,
        0xff829109128b0bd884cb11891ab51a3c,
        0x25ce422cd636209fd58e3eee6bcdb7d7,
        0x86b6a57216f083193e1b361e8a1a5bbf,
        0x38e5c77d01ea3f466707ab5ea8ff4171,
        0x2de7ef9721e4b0550d4fe61188fb1bd3,
        0x5c4feb37d9ad179b297b823812957b8c,
        0x8e36a06b2ac838db09f04ada993caa84,
        0xc6082bd8edaaae4873fb728376565fff,
        0x9b92a729351ab577a2b0de27d713817a,
        0xb7106c3879c5c033015afe43a7bbb48f,
        0xe638c5d1336cc967dd424e375f37904f,
        0xef30fbf0630e9d04f9efc7d242801381,
        0x548ecca55b43556101c39dffff23087,
        0xa3dc4d913d605620dae083b969cba697,
        0x60c413bae203bcfee863fce3d62d7a46,
        0xe3f02a180f232bd7f9e6c41f2ad92bb1,
        0x4983d83fd28ea811148387423931f5c8,
        0x449a77f55b99ac57dcb2131788da3392,
        0x611ba189d789d45401af9d0333b3f9e7,
        0xb67819253374dc0ae0ec21b8ad160234,
        0xf23ff08f2566732b188cdc592a0eb8f7,
        0xc9ac57d3e240265a401dc6270f59c10,
        0x3493b22a21cc4c396552505d8c638d9b,
        0x757fa4336d785da4447251e433ed42fb,
        0x6d2979d4d4a745250ea377dabd44cfb2,
        0x55583ad2a44322ab8ca02871898d1f81,
        0x86373be6909783ffc8bb21b3dda24f12,
        0xc3f3f28407ec57a4a53af471e53285c,
        0x972c409ddb7f2db55ee11ac6a242e45c,
        0x96f938744906740774c33c247ccf85d8,
        0x4cae10232a3558fa26fbc92fab97488b,
        0x8bb0008776ffc7e44db0cc1a2df288b9,
        0x1d0703e4ee2237c7ab53e5b75d921bd7,
        0xff012dbc34f0271cce6d0c1b0d125e3a,
        0x9aea02703d99a98cb9e1b3a368dce85b,
        0xb39755229db1f4de29498e7a13e7cdc2,
        0xc31176b1b646603fc50a528e49742a0e,
        0xead0dc2950f39b1eb2c2edb9407de10d,
        0xea3f3fe33d1d2b7d3cf38b78900dab86,
        0x51bd919a56eb92348316675811dc923,
        0xba5ae9f94b493aa478e08aa4f415cb18,
        0x141e17265a74f46bb369c916cbaf8a25,
        0x6c99c4af650a8451a195d75a7769413b,
        0x342484168e3692419b8ea7e8fdcc8f8d,
        0xaa7a29ea7ae49742f8aa7027b065617d,
        0xd345f319cf8d0c5711c92a1a19cf232c,
        0xbf7956da104bb930529470fbcfa3f60e,
        0xaf3c8a62ae50f00d8dd54ec40c51d402,
        0x9f40c849b5f5405f91589271eefd831e,
        0x82131c9fe93d42fe3eac43b40fe78613,
        0xee5d797779ee1b27b76d3ed1cee66add,
        0xb7438c8a8d29a42710da3eeb0dcaa4f4,
        0x884f37a7a1f9068c7b8dbfb652cfb52,
        0x9b027a35e430ddaa521ef0fd91f39162,
        0xb619b3c28e9fd05efbcd5ead6935a75c,
        0xcad054f32f966043874b2e8163127c7,
        0x8ec4fff59680eaae0077f3dd83fbd947,
        0x50d8597763331f8dcea34c16608a96a7,
        0x6d03608d9f2a6e86dd0d62d96a32751d,
        0x49110668fefb446975dea1bb5742ad75,
        0xde3c54e5dc0bf89137cf5d286ba5868a,
        0x61121e79a40f65000fb426800e5b4f0b,
        0x996944c65744223a5ef06f1eda08fd6,
        0xda3cbe76b9f383e1cde547094cf05431,
        0xa3a2b75fb155f13733c11156ff19d609,
        0xfb4449056e5c6fb2d9a33f42f0a893ad,
        0x128f41399db28643d0743873dc1264a,
        0xff09c9c044dd9342be235156d0bf9197,
        0xcbb652c3d0896219d921f2c49b28d8e7,
        0x61102a46cc01cdf697b666aa7d3d8d45,
        0x717c5e9d4a0731b69d1e33a8f128eedd,
        0xd3498c6de1db846fb5b84c3d08a26402,
        0x1d074123e95f221742bb042dd2decd90,
        0x49dd214c370bbb55e8a3a82b147053be,
        0x18af31dbbab9458eb16b27c0fd1c309f,
        0x61e2d820490e7be32289961803263c34,
        0x107fa373d60153306bcebc6f2ea6aac5,
        0x3df814508cd896e7813397e8a778f8cd,
        0x4021c8146d9e0d33e353d0c73604d58e,
        0xee2c21eb408160983c5ccee03d280f85,
        0xe77f3ff735b6b82a28ab2ed8e3fc8320,
        0x8eee1c68d1cbc4b55eefff30ae3f6028,
        0xfabf471e3d132661b55c0f419db06696,
        0x69a006d6b32d6e23d48dde5999c10f7d,
        0x389f96875b52a0cdaf55c6a03819c6f1,
        0xd349d8dacbf6f4a04625d7953d3190bd,
        0xbe8502448366699e39f5117acfd01714,
        0xa3839a34242c75f7ffc21bd9c630459b,
        0xb3c2ef7bbf449f8af05d8a9a760e9407,
        0x694d27a4f1ba1074a7c2e5445f874b2d,
        0x855c18884723bdcb6dff2cf4849ec19,
        0x58d911a330ce147d06afb9ccb802b7db,
        0xde87764a4427a4aff5db695eda550c2a,
        0xbfa47075ed035846f2016301eb7e4009,
        0xd7335e553652ccbc3f0ff542099a9636,
        0xede815347e14cec1440aa1c612391b,
        0x96e7e4d4efb40213aa73764edddd4ff6,
        0x399c2dd474a47a3f36d286b7e1d3b32b,
        0xcaaeb9876b882f04dc62c5f814d4f79c,
        0x5c7127c96b5c4300fe9954f7999e2f5a,
        0xfe1178bc295c981e59278e0135930986,
        0xe3a9112535f5f53b6a9acc3e49877fd2,
        0x3d6051a6cf2bb75e59ff8f7991cf6bad,
        0x30d97c016d51144b717181ec5f826ba3,
        0xe3b2c049622bdaa3e7e81e99b46920ee,
        0x547744dda2f0145457aacf948f0aca14,
        0x822e4b280fbbaf701b00d1cf2675dacf,
        0x13dae85beaa0a8bb735a39898b93504,
        0xaeed75387d73a822299a17f008c4cd8c,
        0x2d4278deab8e9cdeb21b66e82f85dea7,
        0x5745efd4f8b0dc873484e5f3c83ed61,
        0x456a83da121c2fc61b55c9bd216a36cd,
        0x6ccd4a5d0819113889547d0e69bac59b,
        0xbec7bd6ab8e7169c06c93f34451b5abe,
        0xb9e80fcc7ca8fe72faafc4143960829a,
        0xbbfefb3dd63f00f3f8407e5f20d87c6a,
        0x91b376701a386e5aee6fdbd0738b4c99,
    ];

    /// Standard GCM polynomial basis -> Tower basis.
    pub const FLAT_TO_TOWER: [u128; 128] = [
        0x1,
        0xe9453afbbb5efa683426e20fcdbc3b96,
        0x1c17484568577f0b04c63c03208aeb8a,
        0x4adf5cfe6486e00ca9f6f0b3f58b122,
        0x4bad34793b579f5c90920a4453c26f86,
        0xfc24da72abcee7f5f01fbedeb26a8df9,
        0x1091dcf0350c7dc7c2e119ec5af1fc07,
        0x472c8b0c136435be967e8ef8074dced9,
        0xee63773a41b8bbd26fcb07ebd4630981,
        0x2fc50cfe61e714bbe42ae0de5fd0d8d,
        0x168a685e2f21945aa9736c6bb7c2895c,
        0xdbec3dae32169816645d4935276b15d,
        0x1bcdfffc8342ca4dc8bfedc18a3078d9,
        0x1e81239207e6ef6e793f115bf0d1ddc0,
        0xbe1603d9dcb9eef74e5b36e05726ffaf,
        0xe1b26ab22e51d6585535ccbca9496a06,
        0x9f9e05a29dd55fa844808cc9a48d50c,
        0x21aaba3a74e307cc2ded8391e34e8e9,
        0x4966d3e1afc209d7f157b26e887a38a,
        0xaf7446de9259fba17a5602c30e34c669,
        0xf25b0fd6d577f77f9d1882fb0bc5ba0,
        0x1d459f2a48cefb1c3cd4e7a6ec5dfa4b,
        0x5177981cdf5b750cc65ad9ea7ca055a4,
        0x51f9fbcea7da4578c92da6c12526013e,
        0x5e5568bae10fd0bea4055c77b9a844c3,
        0xe421662a1e1eec508af632be1f0e02a4,
        0x4fb8a006db40f3160af93b49a86074d9,
        0x45ae448d6e7f1d9eb69a344d34af8f84,
        0xb9c51ce3b12188ad65e7759b1f401559,
        0xabbb0931ab3235c58087e2dbc96ad33f,
        0x5c9cf000628598d60736ed8ccf038e67,
        0xb600769f47150f0b5cfaad9450463bed,
        0x41ff7793986a07fac4a9907ae8a743c2,
        0x9285f4c18937b3185fabe5973520296,
        0x4df8dc9851d9e1c3e7a14efcbfb2f95,
        0xf84536296d274eacfca1c8ec05ff86f2,
        0x10a307e4b186622325d30a95cecef780,
        0xb707ef2d98cf44184ddac671e2eb5fe3,
        0xa36bd753c6ba59d052163d58f1bed352,
        0xbb51e68d389f63b3fe34ed01757689b0,
        0x553399b0b5fc844caf168701fe5943e2,
        0x149dde950e34d85250b4a4567313dbce,
        0x4a3936263f0c100aa4c65c24c9f26072,
        0x4104e328f53e6a7de372c31b4ad5ad83,
        0xb1183d7d5bd62290a0a89715d0f4c888,
        0x4d660de92cacf0dd908421c7e6d1808d,
        0xb1d657600dafa9208939ab4849c39960,
        0x3a20e7aba728cd09b64d73cf2f674f4,
        0xe43e9984cf41aa0882197d2781f8b96f,
        0xbad1c62b0bff422854213e279a1c233d,
        0x4d0e6bd946302e439aac65df948a1cfe,
        0xffd379747924682586a493942c8bd1df,
        0xfe5f1194837be346fdb10eba477ab638,
        0x5295b8af5c0ddbed902930dfa570304d,
        0xba080add877d62a18cd4628ef7af6b4c,
        0x1e25371b9377b58089920b6a510400d3,
        0xac7c0e8e02a2200be87117633cbdd070,
        0xf366765716b499d4b7321e9df5959b66,
        0xb339b133a83acbbe7e547facbe195298,
        0x1475d3694c484e493e02607bf9356c65,
        0xe0cef1d5986e8d2d605e21f64226e065,
        0xa558f89882728f0ad97427c3f9a5f8e4,
        0xf912accaae2365e62b05093b2bf33d56,
        0xe131db01ea71d934b2eb168465351fa8,
        0xaa8f05ca85112b1e8297c34477ceeb64,
        0xdc63231f0469178d0d4de381700cb51,
        0x41d4d8767a16e1d2bf0a593c25f52b86,
        0xad26c0aee1dd7aedd2b22cef38dd64e7,
        0x10491ee2eca4e054f64c3d01df6061f8,
        0xfaaf99c9d558bdd129634f9bc0b49d13,
        0x67a7a8aa629a19a5713b939774af76e,
        0x1c447ad4acaa6cf468c10599af589e85,
        0x1bbe72b8a35a9c3f87a1f1858fe5aa7a,
        0x8d64d109f41fd0101dc11cce5fa73a6,
        0xf827b63c8f571568d3cf4c1ee4ecd03e,
        0x5bb2d722803b61c1b08d89d05152ee9b,
        0xf3cb7ef7f453aef94c19b7fce8aa0805,
        0x450d1ab8d3157a5bb23d60c579d34dc9,
        0xa86d9af6cb03acbd901235280394a449,
        0xe97768fce8cdf250bfa8bb1d0878b3e4,
        0xa1951a61df54b357cfcf4ae3ebc3ccfd,
        0xb76dfde0d95a8d217f54a72f0eddffaf,
        0xbabb93003d8bec9bb5efd043338801f,
        0xdb4962025555aab1dabf8c6eda931d,
        0xefd282331287775f9cb76d437afa2af4,
        0x5a68ffc8bb123839157cede80abb56,
        0xaa8cf4dfecd7c6e8756dd13b5c8f5aca,
        0x21af06bb686259ccb7fd58ec495d475,
        0xecdf1c0a39e0e69edd223ac63f94d3cd,
        0x464b5cd033da15250a59b81eb662376d,
        0xfaa1c4106cecddd1e1ef0970d9739a93,
        0xb8ca7cb682820f3876fa81b790ed93c1,
        0xecba8b8b7f03d6c49ad4f151c9260931,
        0x1d60dcb980bbf80cf229556b3903eaef,
        0x5525a3168b2928eb6704455f531f9ce,
        0xe799e7eb44a895f570225704932e2b1a,
        0x4d407b2df1588fdb990fba30221753a7,
        0x5a9bb03388d916788319c89624300d82,
        0xa9d77c570bd47c6c66e124345a17db90,
        0xa9ec560bb73e81d57e752162bbe4f3c,
        0xfa265c428c9da6f28e2fc970136e0b28,
        0xa5743cf56a237597ce580031f065e75e,
        0x137972c4434747054820151b571875b0,
        0x5c8cdc9126773bb5d414b37e60366586,
        0x129391be83f7a47bb70290df3750e40f,
        0xaeda7d495fc263f9b03de9fc7e321746,
        0xb4e1e37de895f7eebdb5b5394b075ef8,
        0xe2b5f04d33cf20822382a35dcc7edc4e,
        0xa9bcd291a1cf815f152fecdcbcccc914,
        0x5aa7ba1307657374613559d3f5f81fa7,
        0x4f5e74a697aee5d693c4698eebae59b5,
        0x155632caedb80d6b686706af56fc4b90,
        0xa68b8340c09a94a676d7d9a0790e3456,
        0xa12400cbbd51083dc4fca4a59fefba1d,
        0x436bbf27feb7ddeff06b53646f98b6b9,
        0xf9c43925d9ee85198e028ccfa403b668,
        0xe832f276830d436561fdd088096c633b,
        0x1bb6e92daca9c758540c1f17d6a3c2f9,
        0xbb665e8a1f6f65dcb9c4864cb7ebf64,
        0xa58c2b939b7520a6fb1195e3a64b9e09,
        0x5d30484d6e9d13e9534ba48d6aa27e29,
        0x8948e62e9301d8fc28508f145c89bcb0,
        0xe70f02d3ff944a7f3fc77b1ef5e28fe3,
        0xb0a4e40faf35483b62a6ac2a434b53f5,
        0x7ff946d827c42ea27368426556c796f,
        0x1e487747cb1f2330293d260d4ef9e331,
        0x5c037a6cfa8c994eeda5fb46a4b26d21,
        0x26f2a0c6d87933fbc981c086e67c361d,
    ];
}

/// Apply a 128x128 GF(2) matrix to a 128-bit vector.
///
/// Uses a precomputed nibble-indexed lookup table: 32 nibbles in the input,
/// each selecting one of 16 precomputed XOR combinations of 4 matrix rows.
/// Reduces 128 masked XORs to 32 table-XOR steps.
#[inline(always)]
fn apply_matrix(matrix: &[u128; 128], v: u128) -> u128 {
    let table = matrix_nibble_table(matrix);
    let mut res = 0u128;
    let mut v = v;
    // 32 nibbles * 16 entries
    for chunk in 0..32 {
        let nib = (v & 0xF) as usize;
        res ^= table[chunk * 16 + nib];
        v >>= 4;
    }
    res
}

/// Lazily-built nibble lookup table for `apply_matrix`.
///
/// Identifies the two known conversion matrices by their distinct first
/// entries (TOWER_TO_FLAT[0] == 0x1, FLAT_TO_TOWER[0] is large); other
/// matrices fall through to a per-matrix fallback cache.
#[inline]
fn matrix_nibble_table(matrix: &[u128; 128]) -> &'static [u128; 32 * 16] {
    use std::sync::OnceLock;

    // The two static conversion matrices have unique first entries.
    if matrix[0] == conversion_matrix::TOWER_TO_FLAT[0]
        && matrix[1] == conversion_matrix::TOWER_TO_FLAT[1]
    {
        static T2F: OnceLock<[u128; 32 * 16]> = OnceLock::new();
        return T2F.get_or_init(|| build_nibble_table(&conversion_matrix::TOWER_TO_FLAT));
    }
    if matrix[0] == conversion_matrix::FLAT_TO_TOWER[0]
        && matrix[1] == conversion_matrix::FLAT_TO_TOWER[1]
    {
        static F2T: OnceLock<[u128; 32 * 16]> = OnceLock::new();
        return F2T.get_or_init(|| build_nibble_table(&conversion_matrix::FLAT_TO_TOWER));
    }

    static FALLBACK: OnceLock<[u128; 32 * 16]> = OnceLock::new();
    FALLBACK.get_or_init(|| build_nibble_table(matrix))
}

fn build_nibble_table(matrix: &[u128; 128]) -> [u128; 32 * 16] {
    let mut table = [0u128; 32 * 16];
    for chunk in 0..32 {
        let r0 = matrix[chunk * 4];
        let r1 = matrix[chunk * 4 + 1];
        let r2 = matrix[chunk * 4 + 2];
        let r3 = matrix[chunk * 4 + 3];
        for nib in 0..16usize {
            let mut acc = 0u128;
            if nib & 1 != 0 {
                acc ^= r0;
            }
            if nib & 2 != 0 {
                acc ^= r1;
            }
            if nib & 4 != 0 {
                acc ^= r2;
            }
            if nib & 8 != 0 {
                acc ^= r3;
            }
            table[chunk * 16 + nib] = acc;
        }
    }
    table
}

// ---------------------------------------------------------------------------
// Flat<Block128> - The Hardware Accelerated Type
// ---------------------------------------------------------------------------

/// Newtype that marks a Block128 element as stored in the flat (polynomial) basis.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Flat<T: TowerField>(pub T);

impl Flat<Block128> {
    pub fn new(val: Block128) -> Self {
        Self(val)
    }
    pub fn inner(self) -> Block128 {
        self.0
    }
}

impl Zeroize for Flat<Block128> {
    fn zeroize(&mut self) {
        self.0 .0 = 0;
    }
}

// ---- Core GF(2^128) CLMUL Math ----

/// Carry-less multiply by the constant 0x87 (x^7 + x^2 + x + 1).
#[inline(always)]
const fn clmul_u128_by_87(a: u128) -> u128 {
    a ^ (a << 1) ^ (a << 2) ^ (a << 7)
}

/// Reduce a 256-bit polynomial (represented as hi and lo 128-bit integers)
/// modulo x^128 + x^7 + x^2 + x + 1.
#[inline(always)]
const fn reduce_gcm_256(x_hi: u128, x_lo: u128) -> u128 {
    // We need to reduce x_hi * x^128 + x_lo
    // x_hi can be up to 127 bits. We split it into lower 64 bits and upper 63 bits
    // to prevent any overflow during the multiplication by 0x87.
    let x1_lo = x_hi as u64 as u128;
    let x1_hi = (x_hi >> 64) as u64 as u128;

    // x1_lo * x^128 reduces to x1_lo * P. Max degree: 64 + 7 = 71. Fits in u128!
    let v1 = clmul_u128_by_87(x1_lo);

    // x1_hi * x^192 reduces to (x1_hi * P) * x^64. Max degree of x1_hi * P is 63 + 7 = 70.
    // Shifting left by 64 gives max degree 134. The overflow is at most 6 bits.
    let v2 = clmul_u128_by_87(x1_hi);
    let v2_shift64 = v2 << 64;
    let v2_overflow = v2 >> 64; // bits that spilled past 128

    // Combine into lo and hi
    let lo = x_lo ^ v1 ^ v2_shift64;
    let hi = v2_overflow; // represents the remaining degrees 128..133

    // hi represents hi * x^128. Reduce it to hi * P.
    // Max degree of hi is 6. hi * P is max 6 + 7 = 13 bits. Fits in u128!
    let v3 = clmul_u128_by_87(hi);

    lo ^ v3
}

/// Square a flat-basis element: expand bits (insert zeros) then reduce
/// modulo the GCM polynomial.
#[inline(always)]
pub fn square_flat_u128(a: u128) -> u128 {
    // Bit-expand each u64 half to u128 (insert zero between bits).
    let lo = a as u64;
    let hi = (a >> 64) as u64;
    let s_lo = expand_bits_u64_to_u128(lo);
    let s_hi = expand_bits_u64_to_u128(hi);
    reduce_gcm_256(s_hi, s_lo)
}

#[inline(always)]
const fn expand_bits_u64_to_u128(v: u64) -> u128 {
    // Classic bit-interleave with zero: spread bits 0..64 into even positions.
    let mut x = v as u128;
    x = (x | (x << 32)) & 0x00000000FFFFFFFF00000000FFFFFFFF;
    x = (x | (x << 16)) & 0x0000FFFF0000FFFF0000FFFF0000FFFF;
    x = (x | (x << 8)) & 0x00FF00FF00FF00FF00FF00FF00FF00FF;
    x = (x | (x << 4)) & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F;
    x = (x | (x << 2)) & 0x33333333333333333333333333333333;
    x = (x | (x << 1)) & 0x55555555555555555555555555555555;
    x
}

/// Raw carry-less multiplication modulo GCM polynomial (flat-basis mul).
///
/// Inputs and output are interpreted as 128-bit polynomials in the flat
/// basis. Used by `PackedBlock128` flat-basis helpers.
#[inline(always)]
#[allow(unreachable_code)]
pub fn clmul_gcm(a: u128, b: u128) -> u128 {
    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    {
        // SAFETY: PCLMULQDQ is part of the static build target, so LLVM may
        // inline this path into ISA-specific release kernels.
        return unsafe { x86_64_clmul::clmul_block128(a, b) };
    }
    #[cfg(all(target_arch = "x86_64", not(target_feature = "pclmulqdq")))]
    {
        if crate::cpu::pclmul_available() {
            // SAFETY: the process-wide runtime backend is selected only after
            // PCLMULQDQ was detected on this CPU.
            return unsafe { x86_64_clmul::clmul_block128(a, b) };
        }
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    {
        // SAFETY: PMULL is part of the static build target.
        return unsafe { aarch64_clmul::clmul_block128(a, b) };
    }
    #[cfg(all(target_arch = "aarch64", not(target_feature = "aes")))]
    {
        if crate::cpu::pmull_available() {
            // SAFETY: PMULL was detected before selecting this backend.
            return unsafe { aarch64_clmul::clmul_block128(a, b) };
        }
    }
    soft_clmul::clmul_block128(a, b)
}

/// Direct PMULL entry point for AArch64 batch kernels which already crossed
/// a runtime/static `aes` feature boundary.
///
/// # Safety
/// The caller must ensure that the target CPU supports the `aes` (PMULL) feature.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "aes")]
pub unsafe fn clmul_gcm_pmull(a: u128, b: u128) -> u128 {
    // SAFETY: inherited `aes`/PMULL target feature.
    unsafe { aarch64_clmul::clmul_block128(a, b) }
}

/// Convert a raw tower-basis u128 to flat-basis.
#[inline(always)]
pub fn tower_to_flat_u128(v: u128) -> u128 {
    apply_matrix(&conversion_matrix::TOWER_TO_FLAT, v)
}

/// Convert a raw flat-basis u128 to tower-basis.
#[inline(always)]
pub fn flat_to_tower_u128(v: u128) -> u128 {
    apply_matrix(&conversion_matrix::FLAT_TO_TOWER, v)
}

#[cfg(target_arch = "x86_64")]
mod x86_64_clmul {
    use super::*;
    use core::arch::x86_64::*;

    #[inline]
    #[target_feature(enable = "pclmulqdq")]
    pub unsafe fn clmul_block128(a: u128, b: u128) -> u128 {
        let a_reg = _mm_set_epi64x((a >> 64) as i64, a as i64);
        let b_reg = _mm_set_epi64x((b >> 64) as i64, b as i64);

        let v0 = _mm_clmulepi64_si128(a_reg, b_reg, 0x00);
        let v1 = _mm_clmulepi64_si128(a_reg, b_reg, 0x11);

        let a_lo_dup = _mm_unpacklo_epi64(a_reg, a_reg);
        let a_hi_dup = _mm_unpackhi_epi64(a_reg, a_reg);
        let b_lo_dup = _mm_unpacklo_epi64(b_reg, b_reg);
        let b_hi_dup = _mm_unpackhi_epi64(b_reg, b_reg);

        let a_xor = _mm_xor_si128(a_lo_dup, a_hi_dup);
        let b_xor = _mm_xor_si128(b_lo_dup, b_hi_dup);

        let v_mid = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
        let v_mid = _mm_xor_si128(_mm_xor_si128(v_mid, v0), v1);

        let v0_u128 = std::mem::transmute::<__m128i, u128>(v0);
        let v1_u128 = std::mem::transmute::<__m128i, u128>(v1);
        let v_mid_u128 = std::mem::transmute::<__m128i, u128>(v_mid);

        let x_lo = v0_u128 ^ (v_mid_u128 << 64);
        let x_hi = v1_u128 ^ (v_mid_u128 >> 64);

        reduce_gcm_256(x_hi, x_lo)
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64_clmul {
    use core::arch::aarch64::*;

    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn pmull(a: u64, b: u64) -> uint64x2_t {
        // SAFETY: inherited `aes`/PMULL target feature. `poly128_t` and
        // `uint64x2_t` are the same 128 raw bits.
        unsafe { core::mem::transmute::<u128, uint64x2_t>(vmull_p64(a, b)) }
    }

    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn clmul_block128(a: u128, b: u128) -> u128 {
        // Binius-style Horner fold. Four independent schoolbook PMULLs
        // produce the product, then two PMULLs by 0x87 reduce it in two
        // x^64 stages. This is the fastest measured M-series variant.
        unsafe {
            let a_lo = a as u64;
            let a_hi = (a >> 64) as u64;
            let b_lo = b as u64;
            let b_hi = (b >> 64) as u64;
            let zero = vdupq_n_u64(0);

            let t0 = pmull(a_lo, b_lo);
            let t1a = pmull(a_lo, b_hi);
            let t1b = pmull(a_hi, b_lo);
            let t2 = pmull(a_hi, b_hi);
            let mut t1 = veorq_u64(t1a, t1b);

            // Horner form t0 + x^64(t1 + x^64 t2), reducing after each
            // shift by x^64. The only overflow in each stage is its high
            // word multiplied by the modulus tail 0x87.
            t1 = veorq_u64(t1, vextq_u64::<1>(zero, t2));
            t1 = veorq_u64(t1, pmull(vgetq_lane_u64::<1>(t2), 0x87));

            let mut t0 = t0;
            t0 = veorq_u64(t0, vextq_u64::<1>(zero, t1));
            t0 = veorq_u64(t0, pmull(vgetq_lane_u64::<1>(t1), 0x87));

            (vgetq_lane_u64::<0>(t0) as u128) | ((vgetq_lane_u64::<1>(t0) as u128) << 64)
        }
    }
}

mod soft_clmul {
    use super::*;

    #[inline(always)]
    pub fn clmul_64x64(a: u64, b: u64) -> u128 {
        let mut res = 0u128;
        let mut b = b as u128;
        let a = a as u128;
        while b != 0 {
            let lsb = b & (!b + 1);
            res ^= a * lsb;
            b ^= lsb;
        }
        res
    }

    #[inline(always)]
    pub fn clmul_block128(a: u128, b: u128) -> u128 {
        let a_lo = a as u64;
        let a_hi = (a >> 64) as u64;
        let b_lo = b as u64;
        let b_hi = (b >> 64) as u64;

        let v0 = clmul_64x64(a_lo, b_lo);
        let v1 = clmul_64x64(a_hi, b_hi);
        let mid = clmul_64x64(a_lo ^ a_hi, b_lo ^ b_hi) ^ v0 ^ v1;

        let x_lo = v0 ^ (mid << 64);
        let x_hi = v1 ^ (mid >> 64);

        reduce_gcm_256(x_hi, x_lo)
    }
}

// ---- Arithmetic Trait Implementations ----

// Addition in GF(2^128) is XOR; clippy's suspicious_arithmetic_impl lint
// assumes additive groups use `+`, which does not apply to binary fields.
#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for Flat<Block128> {
    type Output = Self;
    #[inline(always)]
    fn add(self, r: Self) -> Self {
        Self(Block128(self.0 .0 ^ r.0 .0))
    }
}

impl Sub for Flat<Block128> {
    type Output = Self;
    #[inline(always)]
    fn sub(self, r: Self) -> Self {
        self.add(r)
    }
}

impl Mul for Flat<Block128> {
    type Output = Self;
    #[inline(always)]
    fn mul(self, r: Self) -> Self {
        let a = self.0 .0;
        let b = r.0 .0;

        Self(Block128(clmul_gcm(a, b)))
    }
}

impl AddAssign for Flat<Block128> {
    fn add_assign(&mut self, r: Self) {
        *self = *self + r;
    }
}
impl SubAssign for Flat<Block128> {
    fn sub_assign(&mut self, r: Self) {
        *self = *self - r;
    }
}
impl MulAssign for Flat<Block128> {
    fn mul_assign(&mut self, r: Self) {
        *self = *self * r;
    }
}

// ---- Field Trait Implementations ----

impl CanonicalSerialize for Flat<Block128> {
    fn serialized_size(&self) -> usize {
        16
    }
    fn serialize(&self, w: &mut [u8]) -> Result<(), SerializationError> {
        self.0.serialize(w)
    }
}
impl CanonicalDeserialize for Flat<Block128> {
    fn deserialize(b: &[u8]) -> Result<Self, SerializationError> {
        Block128::deserialize(b).map(Flat)
    }
}

impl From<u8> for Flat<Block128> {
    fn from(v: u8) -> Self {
        Self(Block128::from(v))
    }
}
impl From<u32> for Flat<Block128> {
    fn from(v: u32) -> Self {
        Self(Block128::from(v))
    }
}
impl From<u64> for Flat<Block128> {
    fn from(v: u64) -> Self {
        Self(Block128::from(v))
    }
}
impl From<u128> for Flat<Block128> {
    fn from(v: u128) -> Self {
        Self(Block128::from(v))
    }
}

impl TowerField for Flat<Block128> {
    const BITS: usize = 128;
    const ZERO: Self = Flat(Block128::ZERO);
    const ONE: Self = Flat(Block128::ONE);
    const EXTENSION_TAU: Self = Flat(Block128::EXTENSION_TAU);

    fn invert(&self) -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let tower_bits = apply_matrix(&conversion_matrix::FLAT_TO_TOWER, self.0 .0);
            let tower_inv = Block128(tower_bits).invert();
            let flat_inv_bits = apply_matrix(&conversion_matrix::TOWER_TO_FLAT, tower_inv.0);
            Self(Block128(flat_inv_bits))
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self(Block128(self.0 .0).invert())
        }
    }

    fn from_uniform_bytes(b: &[u8; 32]) -> Self {
        Self(Block128::from_uniform_bytes(b))
    }
}

impl HardwareField for Flat<Block128> {
    #[inline(always)]
    fn to_flat(&self) -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            Self(Block128(apply_matrix(
                &conversion_matrix::TOWER_TO_FLAT,
                self.0 .0,
            )))
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            *self
        }
    }

    #[inline(always)]
    fn to_tower(&self) -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            Self(Block128(apply_matrix(
                &conversion_matrix::FLAT_TO_TOWER,
                self.0 .0,
            )))
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            *self
        }
    }
}

impl HardwareField for Block128 {
    #[inline(always)]
    fn to_flat(&self) -> Self {
        Flat(*self).to_flat().inner()
    }
    #[inline(always)]
    fn to_tower(&self) -> Self {
        Flat(*self).to_tower().inner()
    }
}
