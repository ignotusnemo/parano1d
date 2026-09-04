// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The wallet-capsule PCS: commit one private MLE column, open it at one
//! point. The geometry is chosen so that RE-VERIFYING the opening inside a
//! proof trace is cheap at the adversarial block sizes:
//!
//! - **Rate 1/32** (`CAPSULE_LOG_RATE = 5`, decoupled from `noid_fri`'s
//!   global `LOG_RATE`): provable proximity bits per query scale with
//!   `log2(1/rate)`, so soundness comes from the rate, not from more
//!   queries (each query costs trace slots; rate only deepens the source
//!   tree by a few nodes).
//! - **All trees use the 1-permutation flat feed-forward compress**
//!   (`TAG_CAPSNODE`) — the same node shape as the proof-core PCS Merkle —
//!   and flat-sponge leaves (`TAG_CAPSLEAF`). One permutation per node and
//!   a 2-lane digest carry, versus the 2-permutation sponge nodes of the
//!   generic FRI trees.
//! - **The top `CAPSULE_TAU = 8` variables fold in TWO arity-16 tensor
//!   layers** (source -> mid -> `Code(h)`): tree leaves are 16-symbol fold
//!   cosets, so a query authenticates ONE source leaf and ONE mid leaf
//!   instead of seven per-layer pair paths. The fully folded message `h`
//!   is revealed and the verifier recomputes `Code(h)` itself — there are
//!   no FRI tail rounds, no final-codeword tree and no second query set.
//! - **16-bit pre-query transcript grind** (`CAPSULE_GRIND_BITS`): the
//!   honest prover pays an accepted-output search cost. This is not an
//!   unconditional 16-bit soundness credit: a malicious prover may return
//!   any satisfying nonce, and quantum search is charged through its oracle
//!   query budget.
//!
//! The 64-query, rate-1/32 geometry is a performance configuration, not a
//! release soundness claim. A finite-length proximity/RBR derivation and the
//! whole-chain lifetime union are separate protocol gates.
//!
//! ## Opening protocol (one column, one point)
//!
//! Writing the column as `col(top, low)` with `top` the highest
//! `CAPSULE_TAU` variables, the proof carries:
//! `upper[i] = col(i, x_low)` (the low contraction, `2^TAU` values) and
//! `h = fold(col, beta)` over the top variables (`2^(nv-TAU)` values),
//! where `beta` is drawn AFTER `upper` is absorbed. The verifier checks
//!
//! 1. `sum_i eq(x_top, i) * upper[i] == value` — the claimed opening;
//! 2. `sum_i eq(beta, i) * upper[i] == h(x_low)` — Schwartz–Zippel at the
//!    random `beta` forces `upper` to BE the low contraction of the same
//!    polynomial the fold chain pins;
//! 3. per query: the 16 authenticated source symbols fold (4 binary
//!    tensor steps, challenges `beta[7..4]`) to the queried mid-leaf cell,
//!    and the 16 authenticated mid symbols fold (`beta[3..0]`) to
//!    `Code(h)[pos]` — recomputed from the revealed `h`;
//! 4. both Merkle paths (source-to-cap, mid-to-root) and the grind.
//!
//! The mid layer is committed AFTER `beta[7..4]` are known (its tree root
//! is absorbed before `beta[3..0]`... see the transcript order in
//! [`capsule_open`]) — wait, all eight betas are drawn together after
//! `upper`; the mid commitment is absorbed before the grind and the query
//! draw, which is what binds it. Folding four variables per committed
//! layer is the same higher-arity round the proof-core PCS uses
//! (`LOG_FRI_ARITY = 4`).

use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};
use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::{AdditiveNTT, Block128, Block256, TowerField};
use noid_fri::hasher::{CryptographicHasher, HashOutput};
use noid_fri::Channel;
use noid_poseidon2b::native::compress_flat_feed_forward_with_tag;
use noid_poseidon2b::native::compression::Poseidon2bFlatSponge;
use noid_poseidon2b::native::domain::{TAG_CAPS256, TAG_CAPSLEAF, TAG_CAPSMIX, TAG_CAPSNODE};

use crate::interleaved_commit::{
    build_source_batched_merkle_proof_to_cap, verify_source_batched_merkle_proof_to_cap,
    CommitmentHashBackend, MerkleCap, SourceBatchedMerkleProof, SourceHash, SourceHashMerkleTree,
};

/// log2 of the capsule code's inverse rate. Decoupled from `noid_fri`'s
/// global `LOG_RATE` — only the capsule pays for this depth.
pub const CAPSULE_LOG_RATE: usize = 5;
pub const CAPSULE_RATE: usize = 1 << CAPSULE_LOG_RATE;

/// Top variables handled by the two wide tensor-fold layers.
pub const CAPSULE_TAU: usize = 8;

/// Variables folded per committed layer (arity-16 rounds).
pub const CAPSULE_WIDE_LOG: usize = 4;

/// Symbols per tree leaf: one full fold coset.
pub const CAPSULE_LEAF_SYMBOLS: usize = 1 << CAPSULE_WIDE_LOG;

/// Source-tree cap depth (the commitment ships this layer).
pub const CAPSULE_CAP_DEPTH: usize = 5;

/// Query count. Debug builds use fewer queries to keep test time sane. The
/// release value is fixed by geometry; security still requires the reviewed
/// finite-length proximity/RBR and lifetime analyses.
#[cfg(not(debug_assertions))]
pub const CAPSULE_NUM_QUERIES: usize = 64;
#[cfg(debug_assertions)]
pub const CAPSULE_NUM_QUERIES: usize = 8;

/// Entropy bits carried by one capsule query seed.
pub const CAPSULE_QUERY_SEED_BITS: usize = u128::BITS as usize;

/// Number of field-element transcript seeds needed to sample
/// [`CAPSULE_NUM_QUERIES`] independent `log_len`-bit positions without
/// throwing away the other bits of each 128-bit challenge.
///
/// Query bits are a single LSB-first bit stream: seed 0 bits 0..127, then
/// seed 1 bits 0..127, and so on. Splitting that stream into consecutive
/// `log_len`-bit words preserves exactly the same amount of query entropy as
/// one field-element squeeze per query. In particular, the production owner
/// capsule (`64 * (9 + CAPSULE_LOG_RATE)` bits) needs seven seeds; the debug
/// capsule needs one.
#[inline]
pub const fn capsule_query_seed_count(log_len: usize) -> usize {
    packed_query_seed_count(CAPSULE_NUM_QUERIES, log_len)
}

/// Locate one LSB-first query-index bit in the packed seed stream.
///
/// Returns `(seed_index, bit_index_within_seed)`. This is public so the
/// recursive verifier can use the exact native packing rule without copying
/// arithmetic from the protocol implementation.
#[inline]
pub const fn capsule_query_bit_location(
    query_index: usize,
    query_bit: usize,
    log_len: usize,
) -> (usize, usize) {
    assert!(query_bit < log_len, "query bit is outside the index width");
    let stream_bit = query_index * log_len + query_bit;
    (
        stream_bit / CAPSULE_QUERY_SEED_BITS,
        stream_bit % CAPSULE_QUERY_SEED_BITS,
    )
}

const fn packed_query_seed_count(num_queries: usize, log_len: usize) -> usize {
    let bits = num_queries * log_len;
    bits.div_ceil(CAPSULE_QUERY_SEED_BITS)
}

/// Pre-query accepted-output grind bits (honest prover cost ~2^bits sponge
/// squeezes; not a fixed ROM/QROM soundness credit).
#[cfg(not(debug_assertions))]
pub const CAPSULE_GRIND_BITS: u32 = 16;
#[cfg(debug_assertions)]
pub const CAPSULE_GRIND_BITS: u32 = 6;

const CAPSULE_OPEN_TAG: u128 = 0xCA95_01E0_0AE4_1102;

/// Stage-timing profile for the capsule prover, printed to stderr when
/// `NOID_CAPSULE_PROFILE` is set (same convention as the auth-PCS byte
/// profile). Zero cost when the variable is absent.
fn capsule_profile() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NOID_CAPSULE_PROFILE").is_ok())
}

macro_rules! capsule_stage {
    ($label:expr, $body:expr) => {{
        if capsule_profile() {
            let t = std::time::Instant::now();
            let out = $body;
            eprintln!(
                "capsule {:<14} {:>9.3} ms",
                $label,
                t.elapsed().as_secs_f64() * 1e3
            );
            out
        } else {
            $body
        }
    }};
}

/// Node hasher for every capsule tree: the 1-permutation flat feed-forward
/// compress under `TAG_CAPSNODE`. Leaves are hashed separately (flat
/// sponge); the pair/field/concat entry points are never used on trees
/// whose leaves arrive pre-hashed.
pub struct CapsuleNodeHasher;

impl CryptographicHasher for CapsuleNodeHasher {
    fn hash_pair(&self, _a: &Block128, _b: &Block128) -> HashOutput {
        unreachable!("capsule trees hash leaves via the flat leaf sponge")
    }
    fn hash_field(&self, _elem: &Block128) -> HashOutput {
        unreachable!("capsule trees hash leaves via the flat leaf sponge")
    }
    fn hash_concatenation(&self, _a: &HashOutput, _b: &HashOutput) -> HashOutput {
        unreachable!("capsule trees compress via the tagged feed-forward node")
    }
    fn compress(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        compress_flat_feed_forward_with_tag(TAG_CAPSNODE, a, b)
    }
    fn batch_compress(&self, pairs: &[HashOutput], out: &mut [HashOutput]) {
        noid_poseidon2b::batch::compress_flat_ff_batch_interleaved_with_tag_into(
            TAG_CAPSNODE,
            pairs,
            out,
        );
    }
}

/// Public commitment: the source tree's cap layer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CapsuleCommitment {
    pub cap: MerkleCap,
    pub log_rows: usize,
}

/// Prover state retained between commit and the single opening.
pub struct CapsuleProverState {
    pub encoded: Vec<Block128>,
    tree: SourceHashMerkleTree,
}

/// The opening proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CapsuleOpeningProof {
    /// The claimed evaluation of the column at the opening point.
    pub value: Block128,
    /// `upper[i] = col(top = i, x_low)` — the low contraction (`2^TAU`).
    pub upper_partial_evals: Vec<Block128>,
    /// The fully beta-folded message (`2^(nv - TAU)` values).
    pub h_evals: Vec<Block128>,
    /// Root of the mid layer tree (source folded by `beta[7..4]`).
    pub mid_root: SourceHash,
    /// Pre-query grind nonce.
    pub grind_nonce: u64,
    /// Per query: the 16 source-coset symbols (query-major, coset-minor).
    pub source_symbols: Vec<Block128>,
    pub source_batch: SourceBatchedMerkleProof,
    /// Per query: the 16 mid-coset symbols (query-major, coset-minor).
    pub mid_symbols: Vec<Block128>,
    pub mid_batch: SourceBatchedMerkleProof,
}

impl CapsuleOpeningProof {
    pub fn byte_len(&self) -> usize {
        16 // value
            + self.upper_partial_evals.len() * 16
            + self.h_evals.len() * 16
            + 32 // mid_root
            + 8 // nonce
            + self.source_symbols.len() * 16
            + self.source_batch.siblings.len() * 32
            + self.mid_symbols.len() * 16
            + self.mid_batch.siblings.len() * 32
    }
}

// ---------------------------------------------------------------------------
// Encoding + fold geometry
// ---------------------------------------------------------------------------

/// Rate-`1/32` encoding: `CAPSULE_RATE` window transforms of the message
/// (window `r` spans NTT basis `[r, r + nv)`), concatenated. The same
/// construction as `noid_fri::code::Code::new`, at the capsule's own rate.
/// The windows are independent, so prover-size messages transform in
/// parallel; small messages (the verifier's `Code(h)` re-encode) stay
/// sequential below the dispatch break-even.
pub fn capsule_encode(message: &[Block128], ntt: &AdditiveNTT<Block128>) -> Vec<Block128> {
    let window = |round: u32| {
        let mut temp = message.to_vec();
        ntt.forward_transform(&mut temp, round, 0);
        temp
    };
    let windows: Vec<Vec<Block128>> = if message.len() >= 1024 {
        use rayon::prelude::*;
        (0..CAPSULE_RATE as u32)
            .into_par_iter()
            .map(window)
            .collect()
    } else {
        (0..CAPSULE_RATE as u32).map(window).collect()
    };
    let mut encoding = Vec::with_capacity(message.len() * CAPSULE_RATE);
    for mut w in windows {
        encoding.append(&mut w);
    }
    encoding
}

/// One binary top-variable fold step on code symbols.
///
/// `rc` is the rate-coset (basis window) index, `before_log` the message
/// log-size BEFORE this fold. The twiddle is the window's top basis vector
/// `2^(rc + before_log - 1)`, affine in the query-position bits.
#[inline]
pub fn capsule_high_fold_step(
    r: Block128,
    rc: usize,
    before_log: usize,
    s0: Block128,
    s1: Block128,
) -> Block128 {
    let basis = Block128::from(1u128 << (rc + before_log - 1));
    s1 + (basis + Block128::ONE + r) * s0
}

/// Fold one 16-symbol coset down four variables. `betas` are consumed
/// highest-variable-first (`betas[0]` folds the top variable), matching
/// [`fold_top_vars`]'s per-round order. `syms[k]` is the coset member with
/// top-4-bits `k`.
pub fn capsule_fold16(
    syms: &[Block128],
    rc: usize,
    msg_log_before: usize,
    betas: &[Block128],
) -> Block128 {
    assert_eq!(syms.len(), CAPSULE_LEAF_SYMBOLS);
    assert_eq!(betas.len(), CAPSULE_WIDE_LOG);
    let mut cur: Vec<Block128> = syms.to_vec();
    for (t, &r) in betas.iter().enumerate() {
        let before_log = msg_log_before - t;
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        for k in 0..half {
            next.push(capsule_high_fold_step(
                r,
                rc,
                before_log,
                cur[k],
                cur[k + half],
            ));
        }
        cur = next;
    }
    cur[0]
}

/// Fold the highest `count` variables of a message MLE, one at a time,
/// with `betas[0]` folding the topmost variable first.
pub fn fold_top_vars(message: &[Block128], betas: &[Block128]) -> Vec<Block128> {
    let mut cur = message.to_vec();
    for &r in betas {
        let half = cur.len() / 2;
        for i in 0..half {
            let hi = cur[i + half];
            cur[i] = cur[i] + r * (cur[i] + hi);
        }
        cur.truncate(half);
    }
    cur
}

/// The 16 codeword positions of leaf `leaf` at message log-size `msg_log`
/// (codeword length `CAPSULE_RATE * 2^msg_log`): rate-coset `rc`, low part
/// `local`, member `k` at `rc*2^msg_log + k*2^(msg_log-4) + local`.
pub fn capsule_leaf_positions(msg_log: usize, leaf: usize) -> [usize; CAPSULE_LEAF_SYMBOLS] {
    let per_coset_leaves = 1usize << (msg_log - CAPSULE_WIDE_LOG);
    let rc = leaf / per_coset_leaves;
    let local = leaf % per_coset_leaves;
    std::array::from_fn(|k| (rc << msg_log) + k * per_coset_leaves + local)
}

/// Leaf index + rate-coset of a codeword position.
#[inline]
pub fn capsule_leaf_of_position(msg_log: usize, pos: usize) -> (usize, usize, usize) {
    let per_coset_leaves = 1usize << (msg_log - CAPSULE_WIDE_LOG);
    let rc = pos >> msg_log;
    let local_full = pos & ((1usize << msg_log) - 1);
    let local = local_full & (per_coset_leaves - 1);
    let k = local_full >> (msg_log - CAPSULE_WIDE_LOG);
    (rc * per_coset_leaves + local, rc, k)
}

/// Number of tree leaves at message log-size `msg_log`.
#[inline]
pub fn capsule_leaf_count(msg_log: usize) -> usize {
    CAPSULE_RATE << (msg_log - CAPSULE_WIDE_LOG)
}

/// Tree depth at message log-size `msg_log`.
#[inline]
pub fn capsule_tree_depth(msg_log: usize) -> usize {
    CAPSULE_LOG_RATE + msg_log - CAPSULE_WIDE_LOG
}

/// Flat-sponge leaf hash over one 16-symbol coset: absorbs the message
/// log-size and leaf index as one meta block, then the symbols as flat
/// lanes. The schedule is fixed-length (always 9 rate blocks) and the
/// capacity IV is the dedicated leaf tag, so no padding flush is needed.
pub fn capsule_leaf_hash(msg_log: usize, leaf_index: usize, syms: &[Block128]) -> SourceHash {
    debug_assert_eq!(syms.len(), CAPSULE_LEAF_SYMBOLS);
    let mut sponge = Poseidon2bFlatSponge::with_tag(TAG_CAPSLEAF);
    sponge.update(&(msg_log as u128).to_le_bytes());
    sponge.update(&(leaf_index as u128).to_le_bytes());
    for s in syms {
        sponge.update(&tower_to_flat_u128(s.0).to_le_bytes());
    }
    sponge.finalize_no_pad()
}

/// C1 leaf hash over one fixed 16-symbol GF(2^256) fold-normal coset. Each
/// symbol is encoded as its low then high GF(2^128) coordinate in flat basis.
/// The dedicated tag binds the leaf type and fixed length. Position is bound
/// by the ordered Merkle path, so no redundant metadata permutation is used.
pub fn capsule_leaf_hash_wide(syms: &[Block256]) -> SourceHash {
    debug_assert_eq!(syms.len(), CAPSULE_LEAF_SYMBOLS);
    let mut sponge = Poseidon2bFlatSponge::with_tag(TAG_CAPS256);
    for symbol in syms {
        sponge.update(&tower_to_flat_u128(symbol.lo.0).to_le_bytes());
        sponge.update(&tower_to_flat_u128(symbol.hi.0).to_le_bytes());
    }
    sponge.finalize_no_pad()
}

/// C1 source-leaf hash over the canonical fold-normal base/wide
/// representation.
/// Each of the eight logical positions contributes the bank value followed
/// by the low and high coordinates of its independent wide companion value.
/// The caller supplies those 24 GF(2^128) lanes in exactly that order.
/// The dedicated tag binds the fixed 24-lane shape; the ordered Merkle path
/// binds position, so no redundant metadata permutation is used.
pub fn capsule_leaf_hash_mixed(packed_lanes: &[Block128]) -> SourceHash {
    debug_assert_eq!(packed_lanes.len(), 3 * (CAPSULE_LEAF_SYMBOLS / 2));
    let mut sponge = Poseidon2bFlatSponge::with_tag(TAG_CAPSMIX);
    for lane in packed_lanes {
        sponge.update(&tower_to_flat_u128(lane.0).to_le_bytes());
    }
    sponge.finalize_no_pad()
}

fn build_capsule_tree(codeword: &[Block128], msg_log: usize) -> SourceHashMerkleTree {
    let n_leaves = capsule_leaf_count(msg_log);
    debug_assert_eq!(codeword.len(), CAPSULE_RATE << msg_log);
    use rayon::prelude::*;
    let leaves: Vec<SourceHash> = (0..n_leaves)
        .into_par_iter()
        .with_min_len(64)
        .map(|leaf| {
            let syms: Vec<Block128> = capsule_leaf_positions(msg_log, leaf)
                .iter()
                .map(|&p| codeword[p])
                .collect();
            capsule_leaf_hash(msg_log, leaf, &syms)
        })
        .collect();
    SourceHashMerkleTree::new(
        leaves,
        CommitmentHashBackend::Arithmetic,
        &CapsuleNodeHasher,
    )
}

// ---------------------------------------------------------------------------
// Transcript helpers
// ---------------------------------------------------------------------------

/// Absorb one 32-byte tree digest as two FIELD ELEMENTS. Capsule digests are
/// FLAT-basis lanes (the flat sponge/compress state words), so each 16-byte
/// half is converted flat→tower before entering the tower-lane channel: the
/// absorbed element IS the digest lane, not its bit pattern re-read in the
/// other basis. (The region twin replays the channel in the flat basis, where
/// this element's lane equals the tree column cell — no per-digest basis
/// bridge in-trace.)
fn absorb_digest(channel: &mut Channel, h: &SourceHash) {
    let lo = u128::from_le_bytes(h[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(h[16..].try_into().unwrap());
    channel.observe_field_elem(Block128::from(flat_to_tower_u128(lo)));
    channel.observe_field_elem(Block128::from(flat_to_tower_u128(hi)));
}

/// Absorb a capsule commitment with its own tag and shape metadata so it
/// cannot be confused with another commitment format in a transcript.
pub fn absorb_capsule_commitment(channel: &mut Channel, commitment: &CapsuleCommitment) {
    const CAPSULE_COMMIT_TAG: u128 = 0xCA95_C0DE_C011_1701;
    channel.observe_field_elem(Block128::from(CAPSULE_COMMIT_TAG));
    channel.observe_field_elem(Block128::from(commitment.log_rows as u128));
    channel.observe_field_elem(Block128::from(commitment.cap.hashes.len() as u128));
    for h in &commitment.cap.hashes {
        absorb_digest(channel, h);
    }
}

/// Deterministic pre-query grind: find the smallest nonce whose absorb
/// makes the next squeeze end in `CAPSULE_GRIND_BITS` zero bits.
///
/// Candidate nonces are probed in parallel on transcript copies, one
/// permutation per probe ([`Channel::probe_squeeze`]). Blocks are scanned
/// in order and `find_first` returns the smallest in-block match, so the
/// accepted nonce — and the live transcript, which absorbs only that
/// nonce — is identical to a sequential search's. Block ≈ 2× the expected
/// attempts: the match usually lands in the first block while over-scan
/// past it stays bounded (the LANECHAL grind uses the same sizing).
fn grind_channel(channel: &mut Channel) -> u64 {
    use rayon::prelude::*;
    let mask = (1u128 << CAPSULE_GRIND_BITS) - 1;
    let block: u64 = 1 << (CAPSULE_GRIND_BITS + 1);
    let probe_src: &Channel = channel;
    let mut start: u64 = 0;
    let nonce = loop {
        if let Some(n) = (start..start.saturating_add(block))
            .into_par_iter()
            .find_first(|&n| probe_src.probe_squeeze(Block128::from(n as u128)).0 & mask == 0)
        {
            break n;
        }
        start = start.saturating_add(block);
    };
    channel.observe_field_elem(Block128::from(nonce as u128));
    let _ = channel.get_random_point();
    nonce
}

fn check_grind(channel: &mut Channel, nonce: u64) -> bool {
    let mask = (1u128 << CAPSULE_GRIND_BITS) - 1;
    channel.observe_field_elem(Block128::from(nonce as u128));
    channel.get_random_point().0 & mask == 0
}

/// Decode the capsule's packed transcript seeds into query positions.
///
/// `Block128::0` is the channel's tower-basis bit pattern. Bits are consumed
/// LSB-first across seed boundaries, then each consecutive `log_len`-bit
/// word is interpreted LSB-first as one query index.
pub fn capsule_queries_from_seeds(seeds: &[Block128], log_len: usize) -> Vec<usize> {
    packed_queries_from_seeds(seeds, CAPSULE_NUM_QUERIES, log_len)
}

fn packed_queries_from_seeds(seeds: &[Block128], num_queries: usize, log_len: usize) -> Vec<usize> {
    assert!(log_len > 0, "capsule query width must be non-zero");
    assert!(
        log_len <= usize::BITS as usize,
        "capsule query width exceeds usize"
    );
    assert_eq!(
        seeds.len(),
        packed_query_seed_count(num_queries, log_len),
        "capsule query seed count"
    );

    (0..num_queries)
        .map(|query_index| {
            let mut index = 0usize;
            for query_bit in 0..log_len {
                let (seed_index, seed_bit) =
                    capsule_query_bit_location(query_index, query_bit, log_len);
                let bit = ((seeds[seed_index].0 >> seed_bit) & 1) as usize;
                index |= bit << query_bit;
            }
            index
        })
        .collect()
}

fn draw_queries(channel: &mut Channel, log_len: usize) -> Vec<usize> {
    let seeds = channel.get_random_points(capsule_query_seed_count(log_len));
    capsule_queries_from_seeds(&seeds, log_len)
}

// ---------------------------------------------------------------------------
// Commit / open / verify
// ---------------------------------------------------------------------------

/// Commit a column of `2^nv` values (`nv > CAPSULE_TAU`).
pub fn capsule_commit(column: &[Block128], nv: usize) -> (CapsuleCommitment, CapsuleProverState) {
    assert!(nv > CAPSULE_TAU, "capsule column must exceed the tau fold");
    assert_eq!(column.len(), 1usize << nv);
    if capsule_profile() {
        eprintln!(
            "capsule commit: nv={nv} codeword=2^{} leaves=2^{}",
            nv + CAPSULE_LOG_RATE,
            capsule_tree_depth(nv)
        );
    }
    let ntt = AdditiveNTT::<Block128>::new(nv + CAPSULE_LOG_RATE);
    let encoded = capsule_stage!("commit/encode", capsule_encode(column, &ntt));
    let tree = capsule_stage!("commit/tree", build_capsule_tree(&encoded, nv));
    let cap = MerkleCap {
        hashes: tree.get_layer_at_depth(CAPSULE_CAP_DEPTH),
    };
    (
        CapsuleCommitment { cap, log_rows: nv },
        CapsuleProverState { encoded, tree },
    )
}

/// Open the committed column at `point`. The caller owns the prover
/// state's lifecycle (the wallet wipes the secret-derived encoding after
/// its single opening).
pub fn capsule_open(
    column: &[Block128],
    state: &CapsuleProverState,
    commitment: &CapsuleCommitment,
    point: &[Block128],
    channel: &mut Channel,
) -> CapsuleOpeningProof {
    let nv = commitment.log_rows;
    assert_eq!(column.len(), 1usize << nv);
    assert_eq!(point.len(), nv);
    let low_vars = nv - CAPSULE_TAU;
    let (x_low, _x_top) = point.split_at(low_vars);

    let value = capsule_stage!("open/value", evaluate_slice(column, point));

    // upper[i] = col(top = i, x_low): contract each top-slice at x_low.
    let low_len = 1usize << low_vars;
    let upper: Vec<Block128> = capsule_stage!(
        "open/upper",
        (0..1usize << CAPSULE_TAU)
            .map(|i| evaluate_slice(&column[i * low_len..(i + 1) * low_len], x_low))
            .collect()
    );

    // Transcript: commitment cap, then the claim, then upper; draw beta.
    absorb_capsule_commitment(channel, commitment);
    channel.observe_field_elem(Block128::from(CAPSULE_OPEN_TAG));
    channel.observe_field_elem(value);
    channel.observe_field_elems(point);
    channel.observe_field_elems(&upper);
    let beta: Vec<Block128> = channel.get_random_points(CAPSULE_TAU);

    // Mid layer: fold the top four variables (betas highest-first =
    // beta[7], beta[6], beta[5], beta[4]) and commit its tree.
    let wide_hi: Vec<Block128> = (0..CAPSULE_WIDE_LOG)
        .map(|t| beta[CAPSULE_TAU - 1 - t])
        .collect();
    let mid_msg = capsule_stage!("open/mid_fold", fold_top_vars(column, &wide_hi));
    let mid_log = nv - CAPSULE_WIDE_LOG;
    let mid_ntt = AdditiveNTT::<Block128>::new(mid_log + CAPSULE_LOG_RATE);
    let mid_code = capsule_stage!("open/mid_enc", capsule_encode(&mid_msg, &mid_ntt));
    let mid_tree = capsule_stage!("open/mid_tree", build_capsule_tree(&mid_code, mid_log));
    let mid_root = mid_tree.get_layer_at_depth(0)[0];
    absorb_digest(channel, &mid_root);

    // h: fold the remaining four top variables; absorb it.
    let wide_lo: Vec<Block128> = (0..CAPSULE_WIDE_LOG)
        .map(|t| beta[CAPSULE_WIDE_LOG - 1 - t])
        .collect();
    let h_evals = fold_top_vars(&mid_msg, &wide_lo);
    debug_assert_eq!(h_evals.len(), low_len);
    channel.observe_field_elems(&h_evals);

    // Cross-check the prover's own consistency (debug): the two dot
    // products the verifier will run.
    #[cfg(debug_assertions)]
    {
        let eq_top = eq_ind_partial_eval(_x_top);
        let lhs = eq_top
            .iter()
            .zip(upper.iter())
            .fold(Block128::ZERO, |acc, (&e, &u)| acc + e * u);
        debug_assert_eq!(lhs, value, "upper does not reproduce the claim");
        let eq_beta = eq_ind_partial_eval(&beta);
        let lhs2 = eq_beta
            .iter()
            .zip(upper.iter())
            .fold(Block128::ZERO, |acc, (&e, &u)| acc + e * u);
        debug_assert_eq!(
            lhs2,
            evaluate_slice(&h_evals, x_low),
            "upper does not reproduce h at x_low"
        );
    }

    // Grind, then draw the query positions over the source codeword.
    let grind_nonce = capsule_stage!("open/grind", grind_channel(channel));
    let queries = draw_queries(channel, nv + CAPSULE_LOG_RATE);

    // Reveal the queried source + mid cosets and build the batched paths.
    let mut source_leaves = Vec::with_capacity(queries.len());
    let mut mid_leaves = Vec::with_capacity(queries.len());
    let mut source_symbols = Vec::with_capacity(queries.len() * CAPSULE_LEAF_SYMBOLS);
    let mut mid_symbols = Vec::with_capacity(queries.len() * CAPSULE_LEAF_SYMBOLS);
    for &q in &queries {
        let (leaf, _, _) = capsule_leaf_of_position(nv, q);
        source_leaves.push(leaf);
        for p in capsule_leaf_positions(nv, leaf) {
            source_symbols.push(state.encoded[p]);
        }
        let (mid_leaf, _, _) = capsule_leaf_of_position(mid_log, leaf_to_mid_position(nv, leaf));
        mid_leaves.push(mid_leaf);
        for p in capsule_leaf_positions(mid_log, mid_leaf) {
            mid_symbols.push(mid_code[p]);
        }
    }
    let source_batch = capsule_stage!(
        "open/src_paths",
        build_source_batched_merkle_proof_to_cap(
            &state.tree,
            &source_leaves,
            capsule_tree_depth(nv),
            CAPSULE_CAP_DEPTH,
            CommitmentHashBackend::Arithmetic,
            &CapsuleNodeHasher,
        )
    );
    let mid_batch = capsule_stage!(
        "open/mid_paths",
        build_source_batched_merkle_proof_to_cap(
            &mid_tree,
            &mid_leaves,
            capsule_tree_depth(mid_log),
            0,
            CommitmentHashBackend::Arithmetic,
            &CapsuleNodeHasher,
        )
    );

    CapsuleOpeningProof {
        value,
        upper_partial_evals: upper,
        h_evals,
        mid_root,
        grind_nonce,
        source_symbols,
        source_batch,
        mid_symbols,
        mid_batch,
    }
}

/// A source leaf's folded position in the mid codeword. The fold sends
/// position `rc*2^nv + local_full` to `rc*2^(nv-4) + (local_full mod
/// 2^(nv-4))`, which is exactly the leaf index — kept as a named helper so
/// the trace twin can mirror the definition.
#[inline]
pub fn leaf_to_mid_position(_nv: usize, source_leaf: usize) -> usize {
    source_leaf
}

/// Verify an opening; returns the bound value on success.
pub fn capsule_verify(
    commitment: &CapsuleCommitment,
    point: &[Block128],
    proof: &CapsuleOpeningProof,
    channel: &mut Channel,
) -> Result<Block128, String> {
    let nv = commitment.log_rows;
    if point.len() != nv || nv <= CAPSULE_TAU {
        return Err("capsule shape mismatch".into());
    }
    let low_vars = nv - CAPSULE_TAU;
    let low_len = 1usize << low_vars;
    let (x_low, x_top) = point.split_at(low_vars);
    if proof.upper_partial_evals.len() != 1usize << CAPSULE_TAU
        || proof.h_evals.len() != low_len
        || commitment.cap.hashes.len() != 1usize << CAPSULE_CAP_DEPTH
    {
        return Err("capsule proof shape mismatch".into());
    }
    let nq = CAPSULE_NUM_QUERIES;
    if proof.source_symbols.len() != nq * CAPSULE_LEAF_SYMBOLS
        || proof.mid_symbols.len() != nq * CAPSULE_LEAF_SYMBOLS
    {
        return Err("capsule query symbol count mismatch".into());
    }

    // Replay the transcript.
    absorb_capsule_commitment(channel, commitment);
    channel.observe_field_elem(Block128::from(CAPSULE_OPEN_TAG));
    channel.observe_field_elem(proof.value);
    channel.observe_field_elems(point);
    channel.observe_field_elems(&proof.upper_partial_evals);
    let beta: Vec<Block128> = channel.get_random_points(CAPSULE_TAU);
    absorb_digest(channel, &proof.mid_root);
    channel.observe_field_elems(&proof.h_evals);
    if !check_grind(channel, proof.grind_nonce) {
        return Err("capsule grind check failed".into());
    }
    let queries = draw_queries(channel, nv + CAPSULE_LOG_RATE);

    // Claim checks: upper against the value at x_top, and against h at
    // beta (Schwartz–Zippel binding of the low contraction).
    let eq_top = eq_ind_partial_eval(x_top);
    let derived = eq_top
        .iter()
        .zip(proof.upper_partial_evals.iter())
        .fold(Block128::ZERO, |acc, (&e, &u)| acc + e * u);
    if derived != proof.value {
        return Err("upper partial evals do not reproduce the claim".into());
    }
    let eq_beta = eq_ind_partial_eval(&beta);
    let batched = eq_beta
        .iter()
        .zip(proof.upper_partial_evals.iter())
        .fold(Block128::ZERO, |acc, (&e, &u)| acc + e * u);
    if batched != evaluate_slice(&proof.h_evals, x_low) {
        return Err("upper partial evals do not reproduce h(x_low)".into());
    }

    // Code(h): recomputed locally — no tail commitment.
    let h_ntt = AdditiveNTT::<Block128>::new(low_vars + CAPSULE_LOG_RATE);
    let code_h = capsule_encode(&proof.h_evals, &h_ntt);

    // Per-query fold chain.
    let wide_hi: Vec<Block128> = (0..CAPSULE_WIDE_LOG)
        .map(|t| beta[CAPSULE_TAU - 1 - t])
        .collect();
    let wide_lo: Vec<Block128> = (0..CAPSULE_WIDE_LOG)
        .map(|t| beta[CAPSULE_WIDE_LOG - 1 - t])
        .collect();
    let mid_log = nv - CAPSULE_WIDE_LOG;
    let mut source_leaves = Vec::with_capacity(nq);
    let mut source_leaf_hashes = Vec::with_capacity(nq);
    let mut mid_leaves = Vec::with_capacity(nq);
    let mut mid_leaf_hashes = Vec::with_capacity(nq);
    for (qi, &q) in queries.iter().enumerate() {
        let (leaf, rc, _) = capsule_leaf_of_position(nv, q);
        let syms =
            &proof.source_symbols[qi * CAPSULE_LEAF_SYMBOLS..(qi + 1) * CAPSULE_LEAF_SYMBOLS];
        source_leaves.push(leaf);
        source_leaf_hashes.push(capsule_leaf_hash(nv, leaf, syms));
        let folded = capsule_fold16(syms, rc, nv, &wide_hi);

        let mid_pos = leaf_to_mid_position(nv, leaf);
        let (mid_leaf, mid_rc, mid_k) = capsule_leaf_of_position(mid_log, mid_pos);
        debug_assert_eq!(mid_rc, rc);
        let mid_syms =
            &proof.mid_symbols[qi * CAPSULE_LEAF_SYMBOLS..(qi + 1) * CAPSULE_LEAF_SYMBOLS];
        if mid_syms[mid_k] != folded {
            return Err(format!(
                "query {qi}: source fold does not hit the mid layer"
            ));
        }
        mid_leaves.push(mid_leaf);
        mid_leaf_hashes.push(capsule_leaf_hash(mid_log, mid_leaf, mid_syms));
        let folded2 = capsule_fold16(mid_syms, rc, mid_log, &wide_lo);

        let h_pos = leaf_to_mid_position(mid_log, mid_leaf);
        if code_h[h_pos] != folded2 {
            return Err(format!("query {qi}: mid fold does not hit Code(h)"));
        }
    }

    verify_source_batched_merkle_proof_to_cap(
        &commitment.cap.hashes,
        CAPSULE_CAP_DEPTH,
        &proof.source_batch,
        capsule_tree_depth(nv),
        &source_leaves,
        &source_leaf_hashes,
        CommitmentHashBackend::Arithmetic,
        &CapsuleNodeHasher,
    )
    .map_err(|e| format!("source path verification failed: {e}"))?;
    verify_source_batched_merkle_proof_to_cap(
        std::slice::from_ref(&proof.mid_root),
        0,
        &proof.mid_batch,
        capsule_tree_depth(mid_log),
        &mid_leaves,
        &mid_leaf_hashes,
        CommitmentHashBackend::Arithmetic,
        &CapsuleNodeHasher,
    )
    .map_err(|e| format!("mid path verification failed: {e}"))?;

    Ok(proof.value)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_query_seed_count_and_bit_mapping() {
        // Production owner geometry: 64 independent 14-bit indices consume
        // exactly 896 bits, i.e. seven complete F128 transcript seeds. The
        // debug geometry retains all 8 * 14 bits in one seed.
        assert_eq!(packed_query_seed_count(64, 9 + CAPSULE_LOG_RATE), 7);
        assert_eq!(packed_query_seed_count(8, 9 + CAPSULE_LOG_RATE), 1);
        assert_eq!(
            capsule_query_seed_count(9 + CAPSULE_LOG_RATE),
            if cfg!(debug_assertions) { 1 } else { 7 }
        );

        // Query 9 straddles seed 0 / seed 1: its low two bits are seed-0
        // bits 126..127, followed by seed-1 bits 0..11. Query 63 ends at
        // the very last bit of seed 6.
        assert_eq!(capsule_query_bit_location(9, 0, 14), (0, 126));
        assert_eq!(capsule_query_bit_location(9, 1, 14), (0, 127));
        assert_eq!(capsule_query_bit_location(9, 2, 14), (1, 0));
        assert_eq!(capsule_query_bit_location(9, 13, 14), (1, 11));
        assert_eq!(capsule_query_bit_location(63, 13, 14), (6, 127));

        let mut seeds = vec![Block128::ZERO; 7];
        seeds[0] = Block128::from(u128::MAX);
        seeds[1] = Block128::from(0b1010_0110_1101u128 | (1u128 << 12) | (1u128 << 25));
        seeds[6] = Block128::from(0x2A5Bu128 << 114);
        let queries = packed_queries_from_seeds(&seeds, 64, 14);
        assert_eq!(queries.len(), 64);
        assert!(queries[..9].iter().all(|&q| q == 0x3FFF));
        assert_eq!(queries[9], (0b1010_0110_1101usize << 2) | 0b11);
        assert_eq!(queries[10], 1 | (1 << 13));
        assert_eq!(queries[63], 0x2A5B);
    }

    fn rng_column(nv: usize, seed: u64) -> Vec<Block128> {
        let mut s = seed;
        (0..1usize << nv)
            .map(|_| {
                s = s.wrapping_add(0x9E3779B97F4A7C15);
                let mut z = s;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
                Block128::from(((z as u128) << 64) | (z ^ (z >> 31)) as u128)
            })
            .collect()
    }

    fn rng_point(nv: usize, seed: u64) -> Vec<Block128> {
        let mut vals = rng_column(nv.next_power_of_two().trailing_zeros() as usize + 1, seed);
        vals.truncate(nv);
        vals
    }

    /// The parallel block-scanned grind must accept exactly the nonce the
    /// sequential search would (the smallest satisfying one), leaving the
    /// live transcript byte-identical.
    #[test]
    fn parallel_grind_matches_sequential_smallest() {
        let mask = (1u128 << CAPSULE_GRIND_BITS) - 1;
        for seed in 0..3u64 {
            let mut channel = Channel::new();
            for v in rng_column(3, 900 + seed) {
                channel.observe_field_elem(v);
            }
            let mut sequential = 0u64;
            while channel.probe_squeeze(Block128::from(sequential as u128)).0 & mask != 0 {
                sequential += 1;
            }
            let mut reference = channel.clone();
            let nonce = grind_channel(&mut channel);
            assert_eq!(nonce, sequential, "seed {seed}");
            // Live transcript state matches the reference replay of the
            // accepted nonce: the next challenges coincide.
            reference.observe_field_elem(Block128::from(nonce as u128));
            let _ = reference.get_random_point();
            assert_eq!(channel.get_random_point(), reference.get_random_point());
        }
    }

    /// The wide code-side fold must agree with encode(fold(message)) —
    /// this is the exactness of `capsule_high_fold_step`'s twiddle at the
    /// capsule rate, for BOTH wide layers.
    #[test]
    fn code_fold_matches_message_fold() {
        let nv = 9;
        let column = rng_column(nv, 7);
        let ntt = AdditiveNTT::<Block128>::new(nv + CAPSULE_LOG_RATE);
        let encoded = capsule_encode(&column, &ntt);
        let betas: Vec<Block128> = (0..CAPSULE_TAU as u64)
            .map(|i| rng_column(0, 100 + i)[0])
            .collect();

        // Layer 1: fold the top 4 vars.
        let wide_hi: Vec<Block128> = (0..4).map(|t| betas[CAPSULE_TAU - 1 - t]).collect();
        let mid_msg = fold_top_vars(&column, &wide_hi);
        let mid_ntt = AdditiveNTT::<Block128>::new(nv - 4 + CAPSULE_LOG_RATE);
        let mid_code = capsule_encode(&mid_msg, &mid_ntt);
        for leaf in 0..capsule_leaf_count(nv) {
            let syms: Vec<Block128> = capsule_leaf_positions(nv, leaf)
                .iter()
                .map(|&p| encoded[p])
                .collect();
            let rc = leaf / (1usize << (nv - 4));
            let folded = capsule_fold16(&syms, rc, nv, &wide_hi);
            assert_eq!(
                folded,
                mid_code[leaf_to_mid_position(nv, leaf)],
                "layer-1 fold mismatch at leaf {leaf}"
            );
        }

        // Layer 2: fold the next 4 vars down to Code(h).
        let wide_lo: Vec<Block128> = (0..4).map(|t| betas[3 - t]).collect();
        let h = fold_top_vars(&mid_msg, &wide_lo);
        let h_ntt = AdditiveNTT::<Block128>::new(nv - 8 + CAPSULE_LOG_RATE);
        let code_h = capsule_encode(&h, &h_ntt);
        let mid_log = nv - 4;
        for leaf in 0..capsule_leaf_count(mid_log) {
            let syms: Vec<Block128> = capsule_leaf_positions(mid_log, leaf)
                .iter()
                .map(|&p| mid_code[p])
                .collect();
            let rc = leaf / (1usize << (mid_log - 4));
            let folded = capsule_fold16(&syms, rc, mid_log, &wide_lo);
            assert_eq!(
                folded,
                code_h[leaf_to_mid_position(mid_log, leaf)],
                "layer-2 fold mismatch at leaf {leaf}"
            );
        }
    }

    /// Duplicated code coordinates would silently lower the effective
    /// distance below the nominal rate. The basis-window construction has
    /// exactly ONE structural family of duplicates: position 0 of every
    /// rate window evaluates the novel-basis polynomial at the subspace
    /// zero, where every non-constant basis polynomial vanishes — all
    /// `CAPSULE_RATE` zero positions equal `msg[0]`. That is a distance
    /// slack of `RATE - 1` out of `RATE * 2^nv` coordinates (~0.2%),
    /// identical in kind to the production rate-4 code (3 of 2^11) and
    /// absorbed by the soundness margins. Anything BEYOND those positions
    /// must not collide.
    #[test]
    fn no_duplicate_code_coordinates_beyond_zero_positions() {
        use std::collections::HashMap;
        let nv = 9;
        let ntt = AdditiveNTT::<Block128>::new(nv + CAPSULE_LOG_RATE);
        let words: Vec<Vec<Block128>> = (0..3)
            .map(|s| capsule_encode(&rng_column(nv, 1000 + s), &ntt))
            .collect();
        let n = words[0].len();
        let mut seen: HashMap<(u128, u128, u128), usize> = HashMap::new();
        let mut dups: Vec<usize> = Vec::new();
        for i in 0..n {
            let key = (words[0][i].0, words[1][i].0, words[2][i].0);
            if seen.insert(key, i).is_some() {
                dups.push(i);
            }
        }
        let expected: Vec<usize> = (1..CAPSULE_RATE).map(|rc| rc << nv).collect();
        assert_eq!(
            dups, expected,
            "capsule code duplicates beyond the window zero positions"
        );
    }

    #[test]
    fn roundtrip_sweep_sizes() {
        for nv in [10usize, 11] {
            let column = rng_column(nv, 500 + nv as u64);
            let point = rng_point(nv, 600 + nv as u64);
            let (commitment, state) = capsule_commit(&column, nv);
            let mut ch = Channel::new();
            let proof = capsule_open(&column, &state, &commitment, &point, &mut ch);
            let mut chv = Channel::new();
            let got = capsule_verify(&commitment, &point, &proof, &mut chv)
                .unwrap_or_else(|e| panic!("nv={nv} verify: {e}"));
            assert_eq!(got, evaluate_slice(&column, &point));
        }
    }

    #[test]
    fn roundtrip_and_determinism() {
        let nv = 9;
        let column = rng_column(nv, 42);
        let point = rng_point(nv, 43);
        let (commitment, state) = capsule_commit(&column, nv);
        let mut ch = Channel::new();
        let proof = capsule_open(&column, &state, &commitment, &point, &mut ch);
        assert_eq!(proof.value, evaluate_slice(&column, &point));

        let mut chv = Channel::new();
        let got = capsule_verify(&commitment, &point, &proof, &mut chv).expect("verifies");
        assert_eq!(got, proof.value);
        assert_eq!(
            ch.get_random_point(),
            chv.get_random_point(),
            "packed-query prover/verifier transcript drift"
        );

        // Determinism: byte-identical proofs on re-prove.
        let (c2, s2) = capsule_commit(&column, nv);
        let mut ch2 = Channel::new();
        let p2 = capsule_open(&column, &s2, &c2, &point, &mut ch2);
        assert_eq!(proof.value, p2.value);
        assert_eq!(proof.upper_partial_evals, p2.upper_partial_evals);
        assert_eq!(proof.h_evals, p2.h_evals);
        assert_eq!(proof.mid_root, p2.mid_root);
        assert_eq!(proof.grind_nonce, p2.grind_nonce);
        assert_eq!(proof.source_symbols, p2.source_symbols);
        assert_eq!(proof.source_batch.siblings, p2.source_batch.siblings);
        assert_eq!(proof.mid_symbols, p2.mid_symbols);
        assert_eq!(proof.mid_batch.siblings, p2.mid_batch.siblings);
    }

    #[test]
    fn rejects_tampering() {
        let nv = 9;
        let column = rng_column(nv, 77);
        let point = rng_point(nv, 78);
        let (commitment, state) = capsule_commit(&column, nv);
        let mut ch = Channel::new();
        let proof = capsule_open(&column, &state, &commitment, &point, &mut ch);

        let verify = |p: &CapsuleOpeningProof| {
            let mut chv = Channel::new();
            capsule_verify(&commitment, &point, p, &mut chv)
        };
        assert!(verify(&proof).is_ok());

        let mut bad = proof.clone();
        bad.value = bad.value + Block128::ONE;
        assert!(verify(&bad).is_err(), "tampered value accepted");

        let mut bad = proof.clone();
        bad.upper_partial_evals[3] = bad.upper_partial_evals[3] + Block128::ONE;
        assert!(verify(&bad).is_err(), "tampered upper accepted");

        let mut bad = proof.clone();
        bad.h_evals[0] = bad.h_evals[0] + Block128::ONE;
        assert!(verify(&bad).is_err(), "tampered h accepted");

        let mut bad = proof.clone();
        bad.source_symbols[5] = bad.source_symbols[5] + Block128::ONE;
        assert!(verify(&bad).is_err(), "tampered source symbol accepted");

        let mut bad = proof.clone();
        bad.mid_symbols[5] = bad.mid_symbols[5] + Block128::ONE;
        assert!(verify(&bad).is_err(), "tampered mid symbol accepted");

        let mut bad = proof.clone();
        bad.mid_root[0] ^= 1;
        assert!(verify(&bad).is_err(), "tampered mid root accepted");

        let mut bad = proof.clone();
        bad.grind_nonce ^= 1;
        assert!(verify(&bad).is_err(), "tampered grind nonce accepted");

        if let Some(s) = proof.source_batch.siblings.first() {
            let mut bad = proof.clone();
            bad.source_batch.siblings[0] = {
                let mut x = *s;
                x[0] ^= 1;
                x
            };
            assert!(verify(&bad).is_err(), "tampered source path accepted");
        }

        // A wrong point must fail against the same proof.
        let bad_point = rng_point(nv, 79);
        let mut chv = Channel::new();
        assert!(
            capsule_verify(&commitment, &bad_point, &proof, &mut chv).is_err(),
            "proof accepted at a different point"
        );
    }
}
