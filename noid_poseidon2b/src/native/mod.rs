// SPDX-License-Identifier: Apache-2.0

pub mod compression;
pub mod digest;
pub mod domain;
pub mod permutation;
pub mod proof_node;

pub use compression::{
    compress, compress_flat_feed_forward_with_tag, compress_with_tag, poseidon2b_hash_byte_slices,
    poseidon2b_hash_bytes, Poseidon2bFlatSponge, Poseidon2bSponge,
};
pub use digest::{poseidon2b_digest, poseidon2b_digest_field, poseidon2b_digest_pair};
pub use domain::{
    capacity_iv, capacity_iv_flat, DomainTag, TAG_ACCBLK, TAG_ADDRFIX, TAG_BLOCKHDR, TAG_BYTEHASH,
    TAG_CAPS256, TAG_CLAIMS, TAG_COMMIT, TAG_COMPRESS, TAG_DAWTNSS, TAG_EXSTNOD, TAG_EXSTSLT,
    TAG_FRICHANL, TAG_FRISTATE, TAG_FSCH256, TAG_FSCHALNG, TAG_HISTCLM, TAG_HISTPRF, TAG_HISTTRN,
    TAG_KSCH256, TAG_KSCHANNL, TAG_LANE256, TAG_LANECHAL, TAG_LEAF, TAG_POWHDR, TAG_SEGMENTTREE,
    TAG_TX8X2, TAG_TXROOT,
};
pub use permutation::{permute_flat_u128, sbox_x7, Poseidon2bPermutation};
pub use proof_node::ProofNodeHashVersion;
