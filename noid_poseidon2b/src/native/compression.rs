// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Poseidon2b sponge / compression function.
//!
//! Sponge parameters: t=4, rate=2, cap=2.

use super::domain::{capacity_iv, capacity_iv_flat, DomainTag, TAG_BYTEHASH, TAG_COMPRESS};
use super::permutation::{permute_flat_u128, Poseidon2bPermutation};
use noid_core::{Block128, CanonicalSerialize, TowerField};
use zeroize::Zeroize;

const STATE_SIZE: usize = 4;
/// Number of field lanes absorbed or squeezed per permutation.
pub const RATE: usize = 2;

const PADDING_START: u8 = 0x80;
const PADDING_END: u8 = 0x01;

/// Poseidon2b sponge with t=4, rate=2, capacity=2.
#[derive(Clone)]
pub struct Poseidon2bSponge {
    state: [Block128; STATE_SIZE],
    buffer: [u8; 32],
    filled_bytes: usize,
    permutation: Poseidon2bPermutation,
}

impl std::fmt::Debug for Poseidon2bSponge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Poseidon2bSponge([REDACTED])")
    }
}

impl Zeroize for Poseidon2bSponge {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.filled_bytes = 0;
    }
}

impl Drop for Poseidon2bSponge {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Poseidon2bSponge {}

impl Default for Poseidon2bSponge {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2bSponge {
    pub fn new() -> Self {
        Self {
            state: [Block128::ZERO; STATE_SIZE],
            buffer: [0u8; 32],
            filled_bytes: 0,
            permutation: Poseidon2bPermutation,
        }
    }

    /// Construct a sponge seeded with a capacity IV. See CRYPTO.md §3.
    /// `state[0]`, `state[1]` are zeroed (rate); `state[2]`, `state[3]`
    /// carry the IV.
    pub fn with_iv(iv: [Block128; 2]) -> Self {
        Self {
            state: [Block128::ZERO, Block128::ZERO, iv[0], iv[1]],
            buffer: [0u8; 32],
            filled_bytes: 0,
            permutation: Poseidon2bPermutation,
        }
    }

    /// Absorb raw bytes into the sponge.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.filled_bytes != 0 {
            let to_copy = std::cmp::min(data.len(), 32 - self.filled_bytes);
            self.buffer[self.filled_bytes..self.filled_bytes + to_copy]
                .copy_from_slice(&data[..to_copy]);
            data = &data[to_copy..];
            self.filled_bytes += to_copy;

            if self.filled_bytes == 32 {
                self.permute_buffer();
                self.filled_bytes = 0;
            }
        }

        for chunk in data.chunks_exact(32) {
            self.buffer.copy_from_slice(chunk);
            self.permute_buffer();
        }

        let remaining = data.chunks_exact(32).remainder();
        if !remaining.is_empty() {
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.filled_bytes = remaining.len();
        }
    }

    /// Absorb a single field element.
    pub fn absorb(&mut self, mut elem: Block128) {
        let mut bytes = elem.to_bytes();
        self.update(&bytes);
        bytes.zeroize();
        elem.zeroize();
    }

    /// Absorb two field elements (one rate block).
    pub fn absorb_pair(&mut self, mut a: Block128, mut b: Block128) {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&a.to_bytes());
        bytes[16..].copy_from_slice(&b.to_bytes());
        self.update(&bytes);
        bytes.zeroize();
        a.zeroize();
        b.zeroize();
    }

    /// Finalize and squeeze a 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        fill_padding(&mut self.buffer[self.filled_bytes..]);
        self.permute_buffer();
        self.squeeze_32()
    }

    /// Squeeze a 32-byte digest without applying a padding flush.
    ///
    /// Only sound for **fixed-length** absorb schedules where
    /// `filled_bytes == 0` at squeeze time, i.e. the caller absorbed
    /// a whole number of rate blocks. Domain separation between this
    /// no-pad construction and the pad-flushed [`Self::finalize`] must
    /// come from a construction-specific capacity IV.
    pub fn finalize_no_pad(self) -> [u8; 32] {
        debug_assert_eq!(
            self.filled_bytes, 0,
            "finalize_no_pad requires a whole number of rate blocks"
        );
        self.squeeze_32()
    }

    /// Squeeze two field elements without finalizing (for streaming).
    pub fn squeeze(&mut self) -> [Block128; 2] {
        let out = [self.state[0], self.state[1]];
        self.permutation.permute_mut(&mut self.state);
        out
    }

    /// Rate lanes of the current state — what the next [`Self::squeeze`]
    /// would return — without the squeeze's advance permutation. For
    /// prover-side probes whose state is discarded after one read (grind
    /// loops); the caller must have flushed any buffered absorbs.
    pub fn peek_rate(&self) -> [Block128; 2] {
        debug_assert_eq!(self.filled_bytes, 0, "peek_rate requires a flushed buffer");
        [self.state[0], self.state[1]]
    }

    /// Complete current sponge state after a whole-rate-block absorb.
    ///
    /// Kept crate-private: protocol channels may use it for an exact typed
    /// cross-channel bridge, while ordinary hash callers must not treat the
    /// capacity lanes as a digest or ad-hoc public output.
    pub(crate) fn full_state_after_aligned_absorb(&self) -> [Block128; STATE_SIZE] {
        assert_eq!(
            self.filled_bytes, 0,
            "full-state bridge requires a whole absorb block"
        );
        self.state
    }

    /// Whether the next absorb starts at a fresh rate block. Protocol-level
    /// full-state bridges use this to reject a half-filled transcript rather
    /// than silently changing the close schedule in release builds.
    pub(crate) fn absorb_is_aligned(&self) -> bool {
        self.filled_bytes == 0
    }

    /// Flush any buffered absorb bytes into the state via one padded
    /// permutation, so subsequent `squeeze()` calls are guaranteed to
    /// commit to everything absorbed so far.
    ///
    /// Idempotent when no data is pending *and* the caller has not yet
    /// squeezed. Always safe to call before switching from absorb to
    /// squeeze mode.
    pub fn flush_to_squeeze(&mut self) {
        if self.filled_bytes != 0 {
            fill_padding(&mut self.buffer[self.filled_bytes..]);
            self.permute_buffer();
            self.filled_bytes = 0;
        }
    }

    fn permute_buffer(&mut self) {
        // XOR buffer into rate portion of state
        for i in 0..RATE {
            let mut word = [0u8; 16];
            word.copy_from_slice(&self.buffer[i * 16..(i + 1) * 16]);
            let mut elem = Block128::from(u128::from_le_bytes(word));
            self.state[i] += elem;
            elem.zeroize();
            word.zeroize();
        }
        self.permutation.permute_mut(&mut self.state);
    }

    fn squeeze_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.state[0].to_bytes());
        out[16..].copy_from_slice(&self.state[1].to_bytes());
        out
    }
}

/// 2-to-1 compression of two 32-byte digests. See CRYPTO.md §5.1.
///
/// Two-permutation sponge with capacity IV = `COMPRESS`:
///
/// ```text
/// state = [a0, a1, COMPRESS_hi, COMPRESS_lo]
/// permute
/// state[0] ^= b0; state[1] ^= b1
/// permute
/// return state[0] || state[1]
/// ```
///
/// Domain separation is carried in the capacity IV before any data is
/// absorbed. Uniform with every other sponge-mode primitive in §5.
#[inline]
pub fn compress(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    compress_with_tag(TAG_COMPRESS, a, b)
}

/// 2-to-1 compression of two 32-byte digests under an explicit domain tag.
///
/// This is the same fixed two-permutation schedule as [`compress`], but the
/// capacity IV is caller-selected. Consensus trees must use their own tags
/// rather than relying on the generic `COMPRESS` domain.
#[inline]
pub fn compress_with_tag(tag: DomainTag, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a0 = Block128::from(u128::from_le_bytes(a[..16].try_into().unwrap()));
    let a1 = Block128::from(u128::from_le_bytes(a[16..].try_into().unwrap()));
    let b0 = Block128::from(u128::from_le_bytes(b[..16].try_into().unwrap()));
    let b1 = Block128::from(u128::from_le_bytes(b[16..].try_into().unwrap()));

    let [iv_hi, iv_lo] = capacity_iv(tag);
    let mut state = [a0, a1, iv_hi, iv_lo];
    Poseidon2bPermutation.permute_mut(&mut state);
    state[0] += b0;
    state[1] += b1;
    Poseidon2bPermutation.permute_mut(&mut state);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&state[0].to_bytes());
    out[16..].copy_from_slice(&state[1].to_bytes());
    out
}

/// Domain-separated Poseidon2b hash for variable-length byte strings.
///
/// The capacity IV fixes this as byte hashing, while the caller-supplied
/// domain string is length-prefixed and absorbed before the message. The
/// message length is also absorbed before the message bytes, so concatenation
/// boundaries are canonical and unambiguous.
#[inline]
pub fn poseidon2b_hash_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    poseidon2b_hash_byte_slices(domain, &[bytes])
}

/// Domain-separated Poseidon2b hash over multiple byte slices.
///
/// Every slice is length-prefixed, so `["ab", "c"]` and `["a", "bc"]` are
/// different inputs. This is the preferred helper for canonical transport
/// roots that already have structured byte pieces.
#[inline]
pub fn poseidon2b_hash_byte_slices(domain: &[u8], pieces: &[&[u8]]) -> [u8; 32] {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_BYTEHASH));
    s.update(&(domain.len() as u64).to_le_bytes());
    s.update(domain);
    s.update(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        s.update(&(piece.len() as u64).to_le_bytes());
        s.update(piece);
    }
    s.finalize()
}

#[inline(always)]
fn fill_padding(data: &mut [u8]) {
    debug_assert!(!data.is_empty() && data.len() <= 32);
    data.fill(0);
    data[0] |= PADDING_START;
    data[data.len() - 1] |= PADDING_END;
}

// ---------------------------------------------------------------------------
// Flat-basis (GCM) primitives
// ---------------------------------------------------------------------------
//
// The permutation schedule runs in the flat basis internally
// (`permute_flat_u128`); the constructions below keep their whole state
// there, so data that already lives in the flat basis — F_{2^128} PCS
// codeword values, lane-oriented transcript digests — is absorbed with no
// basis conversion at all. Byte encoding: one lane = 16 little-endian bytes
// read as a u128 flat value.

/// 1-permutation 2-to-1 compression of two 32-byte digests, **flat basis**,
/// with an input-whitening domain tag and left-input feed-forward:
///
/// ```text
/// state = [a0, a1, b0 ^ IV_hi, b1 ^ IV_lo]
/// permute (flat)
/// return (state[0] ^ a0) || (state[1] ^ a1)
/// ```
///
/// One permutation processes the two input digests. The tag selects the
/// whitening value applied to the right input. Capsule and PCS trees hash
/// leaf payloads with their respective leaf formats before using this
/// internal-node compression.
#[inline]
pub fn compress_flat_feed_forward_with_tag(tag: DomainTag, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a0 = u128::from_le_bytes(a[..16].try_into().unwrap());
    let a1 = u128::from_le_bytes(a[16..].try_into().unwrap());
    let b0 = u128::from_le_bytes(b[..16].try_into().unwrap());
    let b1 = u128::from_le_bytes(b[16..].try_into().unwrap());

    let [iv_hi, iv_lo] = capacity_iv_flat(tag);
    let mut state = [a0, a1, b0 ^ iv_hi, b1 ^ iv_lo];
    permute_flat_u128(&mut state);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&(state[0] ^ a0).to_le_bytes());
    out[16..].copy_from_slice(&(state[1] ^ a1).to_le_bytes());
    out
}

/// Poseidon2b sponge whose state lives in the **flat (GCM) basis**.
///
/// Same t=4/rate-2 duplex, buffering and `0x80…01` padding as
/// [`Poseidon2bSponge`], but absorbed bytes are interpreted as flat-basis
/// lanes and the permutation runs with no boundary conversion. Used for the
/// proof-core PCS Merkle leaves, whose payloads are flat F_{2^128} values.
#[derive(Clone)]
pub struct Poseidon2bFlatSponge {
    state: [u128; STATE_SIZE],
    buffer: [u8; 32],
    filled_bytes: usize,
}

impl std::fmt::Debug for Poseidon2bFlatSponge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Poseidon2bFlatSponge([REDACTED])")
    }
}

impl Zeroize for Poseidon2bFlatSponge {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.filled_bytes = 0;
    }
}

impl Drop for Poseidon2bFlatSponge {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Poseidon2bFlatSponge {}

impl Poseidon2bFlatSponge {
    /// Construct a flat sponge seeded with the tag's capacity IV (flat).
    pub fn with_tag(tag: DomainTag) -> Self {
        Self::with_iv_flat(capacity_iv_flat(tag))
    }

    /// Construct a flat sponge from explicit flat capacity-IV words — for
    /// constructions that bind extra domain data (e.g. a fixed message
    /// length) into the capacity alongside the tag.
    pub fn with_iv_flat(iv: [u128; 2]) -> Self {
        Self {
            state: [0, 0, iv[0], iv[1]],
            buffer: [0u8; 32],
            filled_bytes: 0,
        }
    }

    /// Absorb raw bytes (interpreted as flat-basis lanes).
    pub fn update(&mut self, mut data: &[u8]) {
        if self.filled_bytes != 0 {
            let to_copy = std::cmp::min(data.len(), 32 - self.filled_bytes);
            self.buffer[self.filled_bytes..self.filled_bytes + to_copy]
                .copy_from_slice(&data[..to_copy]);
            data = &data[to_copy..];
            self.filled_bytes += to_copy;

            if self.filled_bytes == 32 {
                self.permute_buffer();
                self.filled_bytes = 0;
            }
        }

        for chunk in data.chunks_exact(32) {
            self.buffer.copy_from_slice(chunk);
            self.permute_buffer();
        }

        let remaining = data.chunks_exact(32).remainder();
        if !remaining.is_empty() {
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.filled_bytes = remaining.len();
        }
    }

    /// Finalize with the `0x80…01` pad block and squeeze a 32-byte digest
    /// (the two rate lanes, flat LE bytes).
    pub fn finalize(mut self) -> [u8; 32] {
        fill_padding(&mut self.buffer[self.filled_bytes..]);
        self.permute_buffer();
        self.squeeze_32()
    }

    /// Squeeze a 32-byte digest without a padding flush. Only sound for
    /// **fixed-length** absorb schedules that end block-aligned
    /// (`filled_bytes == 0`); domain separation from the pad-flushed
    /// [`Self::finalize`] must come from the capacity IV (a distinct tag,
    /// with the fixed length bound in — see the PCS fixed-leaf mode).
    pub fn finalize_no_pad(self) -> [u8; 32] {
        debug_assert_eq!(
            self.filled_bytes, 0,
            "finalize_no_pad requires a whole number of rate blocks"
        );
        self.squeeze_32()
    }

    fn squeeze_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.state[0].to_le_bytes());
        out[16..].copy_from_slice(&self.state[1].to_le_bytes());
        out
    }

    fn permute_buffer(&mut self) {
        for i in 0..RATE {
            let mut word = [0u8; 16];
            word.copy_from_slice(&self.buffer[i * 16..(i + 1) * 16]);
            self.state[i] ^= u128::from_le_bytes(word);
        }
        permute_flat_u128(&mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sponge_deterministic() {
        let mut s1 = Poseidon2bSponge::new();
        s1.update(b"hello world");
        let d1 = s1.finalize();

        let mut s2 = Poseidon2bSponge::new();
        s2.update(b"hello world");
        let d2 = s2.finalize();

        assert_eq!(d1, d2);
    }

    #[test]
    fn sponge_debug_is_redacted_and_owned_state_is_zeroizing() {
        fn assert_zeroize<T: Zeroize + zeroize::ZeroizeOnDrop>() {}
        assert_zeroize::<Poseidon2bSponge>();
        assert_zeroize::<Poseidon2bFlatSponge>();

        let mut sponge = Poseidon2bSponge::new();
        sponge.update(&[0xA7; 32]);
        assert_eq!(format!("{sponge:?}"), "Poseidon2bSponge([REDACTED])");

        let mut flat = Poseidon2bFlatSponge::with_iv_flat([0xA7; 2]);
        flat.update(&[0x5C; 32]);
        assert_eq!(format!("{flat:?}"), "Poseidon2bFlatSponge([REDACTED])");
    }

    #[test]
    fn test_sponge_different_inputs() {
        let mut s1 = Poseidon2bSponge::new();
        s1.update(b"hello");
        let d1 = s1.finalize();

        let mut s2 = Poseidon2bSponge::new();
        s2.update(b"world");
        let d2 = s2.finalize();

        assert_ne!(d1, d2);
    }

    #[test]
    fn test_compress_deterministic() {
        let a = [7u8; 32];
        let b = [42u8; 32];
        assert_eq!(compress(&a, &b), compress(&a, &b));
    }

    #[test]
    fn test_compress_distinguishes_order() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(compress(&a, &b), compress(&b, &a));
    }

    #[test]
    fn test_byte_hash_binds_domain_and_length() {
        let ab = poseidon2b_hash_bytes(b"D0", b"ab");
        let ba = poseidon2b_hash_bytes(b"D0", b"ba");
        let other_domain = poseidon2b_hash_bytes(b"D1", b"ab");
        let with_zero = poseidon2b_hash_bytes(b"D0", b"ab\0");
        let split = poseidon2b_hash_byte_slices(b"D0", &[b"a", b"b"]);
        assert_eq!(ab, poseidon2b_hash_bytes(b"D0", b"ab"));
        assert_ne!(ab, ba);
        assert_ne!(ab, other_domain);
        assert_ne!(ab, with_zero);
        assert_ne!(ab, split);
    }

    #[test]
    fn test_absorb_field_elements() {
        let mut sponge = Poseidon2bSponge::new();
        sponge.absorb(Block128::from(42u8));
        sponge.absorb(Block128::from(123u8));
        let _digest = sponge.finalize();
        // Just ensure it doesn't panic
    }

    #[test]
    fn test_compress_ff_deterministic_order_and_tag_sensitive() {
        use super::super::domain::DomainTag;
        let t1 = DomainTag::new(b"FFTESTA_");
        let t2 = DomainTag::new(b"FFTESTB_");
        let a = [7u8; 32];
        let b = [42u8; 32];
        let h = compress_flat_feed_forward_with_tag(t1, &a, &b);
        assert_eq!(h, compress_flat_feed_forward_with_tag(t1, &a, &b));
        assert_ne!(h, compress_flat_feed_forward_with_tag(t1, &b, &a));
        assert_ne!(h, compress_flat_feed_forward_with_tag(t2, &a, &b));
    }

    /// The feed-forward is the one-wayness step: the output must NOT equal
    /// the bare truncated permutation of the whitened input.
    #[test]
    fn test_compress_ff_feed_forward_present() {
        use super::super::domain::{capacity_iv_flat, DomainTag};
        let tag = DomainTag::new(b"FFTESTC_");
        let a = [3u8; 32];
        let b = [9u8; 32];
        let a0 = u128::from_le_bytes(a[..16].try_into().unwrap());
        let a1 = u128::from_le_bytes(a[16..].try_into().unwrap());
        let b0 = u128::from_le_bytes(b[..16].try_into().unwrap());
        let b1 = u128::from_le_bytes(b[16..].try_into().unwrap());
        let [iv_hi, iv_lo] = capacity_iv_flat(tag);
        let mut state = [a0, a1, b0 ^ iv_hi, b1 ^ iv_lo];
        permute_flat_u128(&mut state);
        let mut bare = [0u8; 32];
        bare[..16].copy_from_slice(&state[0].to_le_bytes());
        bare[16..].copy_from_slice(&state[1].to_le_bytes());
        let h = compress_flat_feed_forward_with_tag(tag, &a, &b);
        assert_ne!(h, bare);
    }

    #[test]
    fn test_flat_sponge_deterministic_length_and_tag_bound() {
        use super::super::domain::DomainTag;
        let t1 = DomainTag::new(b"FLSPNGA_");
        let t2 = DomainTag::new(b"FLSPNGB_");
        let data: Vec<u8> = (0..64u8).collect();

        let hash = |tag, bytes: &[u8]| {
            let mut s = Poseidon2bFlatSponge::with_tag(tag);
            s.update(bytes);
            s.finalize()
        };
        assert_eq!(hash(t1, &data), hash(t1, &data));
        assert_ne!(hash(t1, &data), hash(t2, &data));
        // Sponge padding separates a full-block message from its extension.
        assert_ne!(hash(t1, &data[..32]), hash(t1, &data[..48]));
        // Split updates equal one whole update (byte-stream semantics).
        let mut split = Poseidon2bFlatSponge::with_tag(t1);
        split.update(&data[..7]);
        split.update(&data[7..40]);
        split.update(&data[40..]);
        assert_eq!(split.finalize(), hash(t1, &data));
    }

    /// `permute_flat_u128` is exactly the conversion-free core of
    /// `Poseidon2bPermutation::permute_mut`.
    #[test]
    fn test_permute_flat_matches_tower_permutation() {
        use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};
        let tower: [Block128; 4] = std::array::from_fn(|i| Block128::from((i as u128) * 77 + 5));
        let mut expected = tower;
        Poseidon2bPermutation.permute_mut(&mut expected);

        let mut flat: [u128; 4] = std::array::from_fn(|i| tower_to_flat_u128(tower[i].0));
        permute_flat_u128(&mut flat);
        for i in 0..4 {
            assert_eq!(flat_to_tower_u128(flat[i]), expected[i].0, "lane {i}");
        }
    }
}
