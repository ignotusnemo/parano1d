//! The flat-basis source-leaf hash replay reproduces the native tower
//! `source_leaf_hash` under φ. This anchors the recursive source-binding
//! leaf family to the production commitment hash.

use noid_core::Block128;
use noid_fri_binius::interleaved_commit::{source_leaf_hash, CommitmentHashBackend};
use noid_ivc_core::deep_chain::leaf_hash::flat_source_leaf_hash;
use noid_ivc_core::deep_chain::schedule::flat_of_tower_u128;
use noid_ivc_core::field::F128;
use noid_poseidon2b::Poseidon2bSponge;

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

fn tower_flat(b: Block128) -> F128 {
    flat_of_tower_u128(b.0)
}

fn digest_to_flat(d: [u8; 32]) -> [F128; 2] {
    let lo = Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap()));
    let hi = Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap()));
    [tower_flat(lo), tower_flat(hi)]
}

/// The flat replay equals φ(native `source_leaf_hash`) across a few
/// `(log_rows, n_cols, leaf_index)` shapes and random symbols. `flat_lane`
/// of the metadata matches the native `Block128::from(..)` inputs through φ,
/// so the whole chain stays flat with φ only at the symbol/digest boundary.
#[test]
fn flat_source_leaf_matches_native() {
    let hasher = Poseidon2bSponge::new();
    let mut rng = Rng(0x1EAF);
    for (log_rows, n_cols, leaf_index) in [(4usize, 1usize, 0usize), (6, 3, 5), (8, 4, 37)] {
        let symbols_tower: Vec<Block128> = (0..n_cols * 2).map(|_| rng.block()).collect();
        let native = source_leaf_hash(
            CommitmentHashBackend::Arithmetic,
            log_rows,
            n_cols,
            leaf_index,
            &symbols_tower,
            &hasher,
        );

        let symbols_flat: Vec<F128> = symbols_tower.iter().map(|&b| tower_flat(b)).collect();
        let got = flat_source_leaf_hash(log_rows, n_cols, leaf_index, &symbols_flat);
        assert_eq!(
            got,
            digest_to_flat(native),
            "flat source leaf != phi(native) at (log_rows={log_rows}, n_cols={n_cols})"
        );
    }
}
