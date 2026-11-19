//! BaseFold prover/verifier with multi-arity FRI.
//!
//! BaseFold runs `L = log_msg_len` sumcheck rounds in lockstep with codeword
//! folds. The first `log_batch_size` rounds are **row-batch** rounds (combine
//! 2 adjacent SoA lanes within each codeword position). The remaining
//! `log_dim = L − log_batch_size` rounds are **FRI** rounds that fold pairs
//! of codeword positions via `fold_pair`.
//!
//! ## Two-tree commit + multi-arity FRI
//!
//! Two separate Merkle commitments bind the codeword in stages:
//!
//! - **T₁ (initial)** — built in [`super::commit::commit`] before basefold
//!   runs. Leaves contain ONE codeword position's row-batch lanes
//!   (`2^log_batch_size = num_ntts` F_{2^128} per leaf). Small leaves keep
//!   per-query path proofs short and proof size low.
//! - **T₂ (post-row-batch)** — built **inside** [`prove`] right after the
//!   `log_batch_size` row-batch sumcheck rounds. Multi-arity leaves of
//!   `2^arity_0` F_{2^128} group consecutive post-row-batch positions so
//!   one Merkle opening suffices for the first FRI epoch's `arity_0` folds.
//!
//! Subsequent FRI epochs get their own commits via the multi-arity scheme:
//! `arities = [4, 4, 4, 2]` for `log_dim = 14` → 1 (T₂) + 3 (FRI epoch
//! boundaries) commits inside basefold, plus T₁ from outside.
//!
//! ## Per-query work
//!
//! For each FRI query position:
//! 1. Open the **T₁ leaf** (`num_ntts` F_{2^128} = one position's row-batch
//!    lanes) via one Merkle path. Verify against T₁ root.
//! 2. Row-batch-fold the lanes → a single post-row-batch F_{2^128} value.
//! 3. Open the **T₂ leaf** (`2^arity_0` F_{2^128} = the multi-arity coset
//!    for this position's FRI epoch 0) via one Merkle path. Verify against
//!    T₂ root, then **cross-check** that T₂'s value at the queried offset
//!    matches the row-batch-folded value from step 2.
//! 4. FRI-fold T₂'s `2^arity_0` values via arity_0 challenges → one value at
//!    the post-epoch-0 layer.
//! 5. For each subsequent FRI commit i: open the **epoch leaf**
//!    (`2^arity_{i+1}` F_{2^128} values), verify Merkle, locate the position
//!    inside the leaf, check it matches the prior epoch's folded value, then
//!    fold the leaf via arity_{i+1} challenges to produce the next layer's
//!    expected value.
//! 6. After the last epoch, the expected value must match `final_codeword`
//!    at the corresponding (constant) position.
//!
//! ## Why two trees instead of one big-leaf tree
//!
//! Earlier versions used a single tree whose initial leaves bundled
//! `2^arity_0` consecutive codeword positions × `num_ntts` lanes
//! (= `2^11 = 2 KiB` at default params). One Merkle open per query gave the
//! verifier everything for the first FRI epoch. But this inflated each
//! query's initial-leaf payload by `2^arity_0 ×` more than necessary
//! (sending 64 positions when the verifier only needed one position to
//! do row-batch verification, plus the cross-check against T₂).
//!
//! The two-tree split cuts initial-leaf payload by `2^arity_0`× at the cost
//! of one extra Merkle commit on a 32×-smaller codeword — negligible
//! prover-side, ~4× smaller proofs.

use crate::challenger::Challenger;
use crate::field::{F128, F256};
use crate::merkle::{self, Hash, ProofNodeHashVersion};
use crate::ntt::AdditiveNttF128;
use serde::{Deserialize, Serialize};

/// Transcript grinding spent immediately before query-position sampling:
/// the prover searches a nonce whose transcript-bound PoW hash clears this
/// many leading zero bits (one search of `2^QUERY_GRIND_BITS` expected
/// permutations, once per proof), and every query in [`default_fri_queries`]
/// then only needs to close `100 − QUERY_GRIND_BITS` bits. A verifier —
/// native or in-circuit — pays ONE extra permutation to check the nonce,
/// while the query-count reduction removes whole Merkle-path replays per
/// proof; the trade is strongly verifier-favorable. 16 bits keeps the
/// prover's grind under ~0.5 s single-threaded.
pub const QUERY_GRIND_BITS: u32 = 16;

/// Historical query-count floor at **rate 1/2** (`log_inv_rate = 1`). The
/// active count is derived by [`checked_fri_configuration`] from both the
/// rate and the actual codeword length, and is never allowed below this
/// floor. Keeping the floor avoids silently weakening an already-published
/// configuration when the finite-length calculation happens to round down.
///
/// For an RS word of length `n`, rate `rho`, and relative distance
/// `delta = 1-rho`, the finite UDR radius used here is
///
/// ```text
/// gamma(n,rho) = delta/2 - 3/(delta*n).
/// ```
///
/// This is the same corrected finite-length radius used by Ligerito's UDR
/// ledger. The configuration check enforces the theorem range
/// `delta/3 <= gamma`, not merely `gamma > 0`. Within that radius the prover
/// is consistent with at most one codeword, and each query catches a
/// `gamma`-far prover with probability at least `gamma`:
///
/// ```text
/// soundness error ≤ 2^−QUERY_GRIND_BITS · (1 − γ)^t
/// ```
///
/// For 100 bits total we need
///
/// ```text
/// t · (−log₂(1 − γ)) ≥ 100 − QUERY_GRIND_BITS.
/// ```
///
/// The fold-consistency exceptional-set factor is
/// `a = gamma(n,rho)*n + 1`, so its error is `a/2^128`: it is explicitly
/// length-dependent and loses about one bit whenever `n` doubles.
/// [`checked_fri_configuration`] rejects a domain/rate whose proximity term
/// falls below the 100-bit BaseFold target. BaseFold has no fold-challenge
/// grind with which to repair such a domain.
pub const DEFAULT_FRI_QUERIES: usize = 204;

/// Consensus query floor for the rate-1/4 BaseFold profile used by the
/// production History relation.  The C1 profile raises the previous floor of
/// 125 to 133 without changing the code rate or any codeword domain.
pub const BASEFOLD_RATE_QUARTER_C1_QUERIES: usize = 133;

/// BaseFold's published classical query/proximity target. This is separate
/// from the authorization capsule's QROM diagnostic.
pub const BASEFOLD_UDR_TARGET_BITS: u32 = 100;

const BASEFOLD_MAX_PUBLISHED_LOG_INV_RATE: usize = 5;
const BASEFOLD_QUERY_FLOORS: [usize; BASEFOLD_MAX_PUBLISHED_LOG_INV_RATE] = [
    DEFAULT_FRI_QUERIES,
    BASEFOLD_RATE_QUARTER_C1_QUERIES,
    102,
    93,
    89,
];

/// Reviewed finite-length UDR configuration for one actual BaseFold domain.
/// `log_domain_len = log_msg_cols + log_inv_rate` and therefore identifies
/// the RS codeword length, not the total interleaved witness length.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BaseFoldUdrConfiguration {
    pub log_msg_cols: usize,
    pub log_inv_rate: usize,
    pub log_domain_len: usize,
    pub domain_len: usize,
    pub relative_distance: f64,
    pub proximity_radius: f64,
    pub per_query_bits: f64,
    pub query_count: usize,
    pub query_term_bits: f64,
    pub proximity_term_bits: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseFoldUdrConfigError {
    UnsupportedInverseRate,
    DomainLengthOverflow,
    FiniteLengthTheoremPrecondition,
    ProximityTargetNotMet,
}

/// Derive and validate the exact domain/rate-dependent BaseFold UDR ledger.
///
/// The integer precondition is `delta^2*n >= 18`, which is equivalent to the
/// required lower endpoint `gamma >= delta/3` for the selected maximal
/// finite radius. Query counts are the minimum needed for the remaining
/// `100-QUERY_GRIND_BITS` query bits, clamped to the consensus rate-specific
/// floors.  In particular, the rate-1/4 floor is the selected C1 History
/// count, which is deliberately stronger than this classical target.  The
/// grind is a classical BaseFold transcript cost; this function makes no QROM
/// claim and is not used by the auth capsule.
pub fn checked_fri_configuration(
    log_msg_cols: usize,
    log_inv_rate: usize,
) -> Result<BaseFoldUdrConfiguration, BaseFoldUdrConfigError> {
    if !(1..=BASEFOLD_MAX_PUBLISHED_LOG_INV_RATE).contains(&log_inv_rate) {
        return Err(BaseFoldUdrConfigError::UnsupportedInverseRate);
    }
    let log_domain_len = log_msg_cols
        .checked_add(log_inv_rate)
        .ok_or(BaseFoldUdrConfigError::DomainLengthOverflow)?;
    if log_domain_len >= usize::BITS as usize {
        return Err(BaseFoldUdrConfigError::DomainLengthOverflow);
    }
    let domain_len = 1usize << log_domain_len;

    // delta=(R-1)/R. Check delta^2*n >= 18 without floating-point
    // comparison; all supported R and platform-sized n fit comfortably in
    // u128.
    let inverse_rate = 1u128 << log_inv_rate;
    let distance_numerator = inverse_rate - 1;
    let n = domain_len as u128;
    if distance_numerator * distance_numerator * n < 18 * inverse_rate * inverse_rate {
        return Err(BaseFoldUdrConfigError::FiniteLengthTheoremPrecondition);
    }

    let relative_distance = distance_numerator as f64 / inverse_rate as f64;
    let proximity_radius = relative_distance / 2.0 - 3.0 / (relative_distance * domain_len as f64);
    let per_query_bits = -(1.0 - proximity_radius).log2();
    let query_bits_needed = BASEFOLD_UDR_TARGET_BITS.saturating_sub(QUERY_GRIND_BITS) as f64;
    let derived_query_count = (query_bits_needed / per_query_bits).ceil() as usize;
    let query_count = derived_query_count.max(BASEFOLD_QUERY_FLOORS[log_inv_rate - 1]);
    let query_term_bits = query_count as f64 * per_query_bits + QUERY_GRIND_BITS as f64;

    // Corrected UDR exceptional-set factor, shared algebraically with the
    // Ligerito analysis: a=gamma*n+1 and eps_pg=128-log2(a).
    let proximity_term_bits = 128.0 - (proximity_radius * domain_len as f64 + 1.0).log2();
    if proximity_term_bits + 1e-9 < BASEFOLD_UDR_TARGET_BITS as f64 {
        return Err(BaseFoldUdrConfigError::ProximityTargetNotMet);
    }
    debug_assert!(query_term_bits + 1e-9 >= BASEFOLD_UDR_TARGET_BITS as f64);

    Ok(BaseFoldUdrConfiguration {
        log_msg_cols,
        log_inv_rate,
        log_domain_len,
        domain_len,
        relative_distance,
        proximity_radius,
        per_query_bits,
        query_count,
        query_term_bits,
        proximity_term_bits,
    })
}

/// Fail-closed query count for one actual BaseFold message domain and rate.
/// New rates or domains outside the reviewed finite-length envelope panic at
/// configuration construction rather than silently inheriting a rate-only
/// count.
pub fn default_fri_queries(log_msg_cols: usize, log_inv_rate: usize) -> usize {
    checked_fri_configuration(log_msg_cols, log_inv_rate)
        .unwrap_or_else(|error| {
            panic!(
                "unsupported BaseFold UDR configuration: log_msg_cols={log_msg_cols}, \
                 log_inv_rate={log_inv_rate}, error={error:?}"
            )
        })
        .query_count
}

/// FRI layers of at most this many F_{2^128} elements are sent PLAINTEXT
/// (absorbed whole into the transcript at their epoch boundary) instead of
/// Merkle-committed. Every deeper epoch tree disappears: queries read the
/// layer directly and the verifier folds it to the final codeword once.
/// The one-time absorb costs `len/2` permutations while committed epochs
/// cost every query a leaf hash plus a Merkle path — the crossover sits in
/// the thousands of elements for ~100 queries, so 2^10 keeps a safety
/// margin on both proof bytes (≤16 KB of plaintext) and absorb work.
pub const PLAINTEXT_TAIL_MAX_F128: usize = 1024;

/// The FRI commit layout under the plaintext-tail rule, derived purely from
/// the shape (shared by the prover, the verifier, and in-circuit replays so
/// they can never disagree): how many epoch boundaries carry Merkle
/// commitments, and — if some boundary layer fits the plaintext cutoff —
/// that layer's length and the number of FRI rounds folded before it.
///
/// Boundaries are indexed by the epoch they FEED: boundary `b` (for
/// `b in 1..arities.len()`) is the layer entering epoch `b`, of length
/// `2^(k_code − Σ arities[..b])`. The first boundary at or below
/// [`PLAINTEXT_TAIL_MAX_F128`] becomes the tail; boundaries past it commit
/// nothing.
pub fn fri_commit_layout(k_code: usize, arities: &[usize]) -> (usize, Option<(usize, usize)>) {
    let mut cum_arity = 0usize;
    for b in 1..arities.len() {
        cum_arity += arities[b - 1];
        let layer_len = 1usize << (k_code - cum_arity);
        if layer_len <= PLAINTEXT_TAIL_MAX_F128 {
            return (b - 1, Some((layer_len, cum_arity)));
        }
    }
    (arities.len().saturating_sub(1), None)
}

/// Derive `n` query positions from the transcript with ONE vector squeeze:
/// each squeezed lane yields `floor(128 / k_code)` positions as consecutive
/// `k_code`-bit windows of its 128-bit flat pattern (low windows first).
/// Shared by the prover and the verifier so the derivation can never drift.
pub fn sample_query_positions<Ch: Challenger>(
    challenger: &mut Ch,
    n: usize,
    k_code: usize,
) -> Vec<usize> {
    assert!(k_code > 0 && k_code <= 64, "position windows fit a lane");
    let per_lane = 128 / k_code;
    let n_lanes = n.div_ceil(per_lane);
    let lanes = challenger.sample_f128_vec(n_lanes);
    let mask = (1u128 << k_code) - 1;
    let mut out = Vec::with_capacity(n);
    'lanes: for lane in lanes {
        let full = ((lane.hi as u128) << 64) | lane.lo as u128;
        for w in 0..per_lane {
            if out.len() == n {
                break 'lanes;
            }
            out.push(((full >> (w * k_code)) & mask) as usize);
        }
    }
    out
}

/// Per-round sumcheck message: `u_0 = u(0)`, `u_2 = u(∞)`. Middle coeff is
/// derived by the verifier from the running claim: `u_1 = T_r + u_2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundMessage {
    pub u_0: F128,
    pub u_2: F128,
}

/// Per-epoch FRI commitment: root of the folded codeword's Merkle tree.
/// (Length = `arities.len() − 1` since the last epoch is sent in plaintext.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundCommitment {
    pub root: Hash,
}

/// A single FRI query opening (multi-arity layout). Each query carries its
/// own full-depth Merkle paths: paths are deliberately NOT deduplicated
/// across queries, so the verification schedule is a pure function of the
/// commitment shape (query count × fixed tree depths) rather than of the
/// sampled positions. A replay of this verifier inside an arithmetic trace
/// needs that fixed schedule; the byte cost of the duplicated upper-path
/// siblings is priced in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryOpening {
    /// Random initial codeword position in `[0, 2^k_code)`.
    pub position: usize,
    /// Initial Merkle leaf: `2^log_batch_size = num_ntts` F_{2^128} values
    /// — the row-batch lanes for ONE codeword position. Verifier row-batch-
    /// folds these (using `log_batch_size` sumcheck challenges) down to a
    /// single F_{2^128} value, then cross-checks against `post_row_batch_leaf`.
    pub initial_leaf: Vec<F128>,
    /// Merkle path for `initial_leaf` in the T1 (initial) tree; length is
    /// exactly `k_code`.
    pub initial_path: Vec<Hash>,
    /// Multi-arity post-row-batch leaf: `2^arity_0` F_{2^128} values covering
    /// `2^arity_0` consecutive post-row-batch codeword positions (including
    /// the queried one). Enables the verifier to do `arity_0` consecutive
    /// FRI folds with a single Merkle opening.
    pub post_row_batch_leaf: Vec<F128>,
    /// Merkle path for `post_row_batch_leaf` in the T2 tree; length is
    /// exactly `k_code − arity_0`. Empty iff `arities.is_empty()`.
    pub post_row_batch_path: Vec<Hash>,
    /// One entry per FRI commit (= `arities.len() − 1` entries; last epoch
    /// sends `final_codeword` in plaintext). Entry `i` is the coset of
    /// `2^arities[i+1]` F_{2^128} values committed at the end of epoch `i`,
    /// which is the input to epoch `i+1`'s arity_{i+1} folds.
    pub epoch_leaves: Vec<Vec<F128>>,
    /// Merkle path per epoch leaf, aligned with `epoch_leaves`; entry `i`
    /// has length `k_code − Σ_{j≤i+1} arities[j]`.
    pub epoch_paths: Vec<Vec<Hash>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseFoldProof {
    /// Sumcheck round messages, length `L = log_msg_len`.
    pub round_messages: Vec<RoundMessage>,
    /// Commitment to the **post-row-batch** codeword (= initial codeword after
    /// `log_batch_size` row-batch sumcheck folds). Inserted into the transcript
    /// right after the row-batch rounds and before the first FRI round. Multi-
    /// arity leaves of size `2^arity_0` F_{2^128} support the first FRI epoch
    /// with one Merkle opening per query.
    pub post_row_batch_commit: RoundCommitment,
    /// FRI epoch commitments, length `arities.len() − 1` (last epoch
    /// plaintext).
    pub round_commitments: Vec<RoundCommitment>,
    pub final_a: F128,
    pub final_b: F128,
    /// Final codeword (length `2^log_inv_rate`, must be constant).
    pub final_codeword: Vec<F128>,
    /// The plaintext-tail FRI layer (see [`PLAINTEXT_TAIL_MAX_F128`]):
    /// absorbed whole into the transcript at its epoch boundary in place of
    /// a Merkle commitment. Empty iff the shape has no qualifying boundary.
    pub plaintext_tail: Vec<F128>,
    /// Transcript-grinding nonce spent before query sampling
    /// ([`QUERY_GRIND_BITS`] leading zero bits).
    pub pow_nonce: u64,
    /// Per-query openings, each with its own independent Merkle paths (see
    /// [`QueryOpening`] for why paths are not deduplicated across queries).
    pub queries: Vec<QueryOpening>,
}

/// C1 sumcheck message. The committed polynomial remains F128-valued, while
/// every algebraic message and challenge after commitment lives in F256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C1RoundMessage {
    pub u_0: F256,
    pub u_2: F256,
}

/// One C1 FRI query. The T1 leaf is the original F128 codeword commitment;
/// every layer after the first wide fold is encoded canonically as F256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C1QueryOpening {
    pub position: usize,
    pub initial_leaf: Vec<F128>,
    pub initial_path: Vec<Hash>,
    pub post_row_batch_leaf: Vec<F256>,
    pub post_row_batch_path: Vec<Hash>,
    pub epoch_leaves: Vec<Vec<F256>>,
    pub epoch_paths: Vec<Vec<Hash>>,
}

/// BaseFold proof for the C1 History profile. T1 and its root are unchanged;
/// sumcheck messages, folded codewords, FRI leaves, and terminal values are
/// all F256 values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C1BaseFoldProof {
    pub round_messages: Vec<C1RoundMessage>,
    pub post_row_batch_commit: RoundCommitment,
    pub round_commitments: Vec<RoundCommitment>,
    pub final_a: F256,
    pub final_b: F256,
    pub final_codeword: Vec<F256>,
    pub plaintext_tail: Vec<F256>,
    pub pow_nonce: u64,
    pub queries: Vec<C1QueryOpening>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    SumcheckFinalMismatch,
    FinalCodewordNotConstant,
    SumcheckFriMismatch,
    /// The pre-query transcript-grinding nonce fails its
    /// [`QUERY_GRIND_BITS`] leading-zero check.
    GrindingFailed,
    InitialMerkleFailed {
        query_index: usize,
    },
    RoundMerkleFailed {
        query_index: usize,
        epoch: usize,
    },
    FoldMismatch {
        query_index: usize,
        epoch: usize,
    },
    InvalidProofShape,
}

/// One FRI fold step (matches DP24 `fold_pair`):
/// ```text
///   v += u; u += v · twiddle
///   result = u + r · (u + v)
/// ```
fn fold_pair(twiddle: F128, u_in: F128, v_in: F128, r: F128) -> F128 {
    let v = v_in + u_in;
    let u = u_in + v * twiddle;
    u + r * (u + v)
}

/// Fused row-batch fold: collapse each codeword position's `2^k` lanes down to
/// a single value using all `k` row-batch challenges (`r_0..r_{k-1}` in round
/// order) in one streaming pass. Equivalent to `k` successive per-round
/// row-batch folds, but reads the codeword once instead of `k` times — the
/// intermediate lane values never leave registers/L1, so memory traffic drops
/// from ~2× the codeword (read full + write half, ×k rounds) to ~1× (read full
/// once + write `n_positions`). Byte-identical output: each surviving lane is
/// the same nested fold of its position's input lanes.
///
/// Writes `n_positions = codeword.len() / 2^k` outputs into `out[..]`.
fn row_batch_fold_all(codeword: &[F128], out: &mut [F128], challenges: &[F128]) -> usize {
    use rayon::prelude::*;
    let num_ntts = 1usize << challenges.len();
    debug_assert_eq!(codeword.len() % num_ntts, 0);
    let n_positions = codeword.len() / num_ntts;
    // One reusable scratch buffer per parallel chunk (not per position), so the
    // hot inner fold is allocation-free regardless of `num_ntts`.
    const CHUNK: usize = 256;
    out[..n_positions]
        .par_chunks_mut(CHUNK)
        .enumerate()
        .for_each(|(ci, out_chunk)| {
            let mut buf = vec![F128::ZERO; num_ntts];
            for (k, slot) in out_chunk.iter_mut().enumerate() {
                let base = (ci * CHUNK + k) * num_ntts;
                buf.copy_from_slice(&codeword[base..base + num_ntts]);
                let mut len = num_ntts;
                for &r in challenges {
                    let half = len / 2;
                    for j in 0..half {
                        let u = buf[2 * j];
                        let v = buf[2 * j + 1];
                        buf[j] = u + r * (u + v);
                    }
                    len = half;
                }
                *slot = buf[0];
            }
        });
    n_positions
}

/// FRI fold of a single-lane codeword at the given layer + challenge.
/// Writes `new_len = codeword.len()/2` outputs into `out[..new_len]`.
fn fri_fold_codeword(
    codeword: &[F128],
    out: &mut [F128],
    ntt: &AdditiveNttF128,
    layer: usize,
    challenge: F128,
) -> usize {
    use rayon::prelude::*;
    let new_len = codeword.len() / 2;
    out[..new_len]
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, slot)| {
            let u = codeword[2 * i];
            let v = codeword[2 * i + 1];
            let twiddle = ntt.twiddle(layer, i);
            *slot = fold_pair(twiddle, u, v, challenge);
        });
    new_len
}

/// Fold one row-batch lanes-stack (length `2^a` for `a = challenges.len()`)
/// down to a single F_{2^128} via `a` row-batch folds.
fn row_batch_fold_one(lanes: &[F128], challenges: &[F128]) -> F128 {
    let mut buf = lanes.to_vec();
    for &r in challenges {
        let half = buf.len() / 2;
        let mut new_buf = Vec::with_capacity(half);
        for j in 0..half {
            let u = buf[2 * j];
            let v = buf[2 * j + 1];
            new_buf.push(u + r * (u + v));
        }
        buf = new_buf;
    }
    debug_assert_eq!(buf.len(), 1);
    buf[0]
}

/// Fold a FRI coset of `2^a` values down to one value via `a` FRI folds.
///
/// - `coset` has length `2^challenges.len()`.
/// - The coset lives at `input_layer` (so the first fold's post-fold layer is
///   `input_layer − 1`).
/// - `coset_idx` is the index of this coset within the `input_layer`-th codeword
///   divided by `2^a`. (For epoch `i` queries, `coset_idx = position >> sum_arities_through_i`.)
fn fri_fold_coset(
    coset: &[F128],
    challenges: &[F128],
    ntt: &AdditiveNttF128,
    input_layer: usize,
    coset_idx: usize,
) -> F128 {
    debug_assert_eq!(coset.len(), 1 << challenges.len());
    let mut buf = coset.to_vec();
    for (k, &r) in challenges.iter().enumerate() {
        // Post-fold layer for this fold step.
        let post_fold_layer = input_layer - k - 1;
        let n = buf.len() / 2;
        let mut new_buf = Vec::with_capacity(n);
        for j in 0..n {
            let u = buf[2 * j];
            let v = buf[2 * j + 1];
            // Position in the post-fold layer of this fold's output.
            // Coset occupies `[coset_idx * 2^(a-k-1) .. (coset_idx+1) * 2^(a-k-1))` in the post-fold layer.
            let pos = coset_idx * n + j;
            let twiddle = ntt.twiddle(post_fold_layer, pos);
            new_buf.push(fold_pair(twiddle, u, v, r));
        }
        buf = new_buf;
    }
    debug_assert_eq!(buf.len(), 1);
    buf[0]
}

/// Serialize a slice of `F128` to little-endian bytes (16 bytes per element).
fn f128_slice_to_bytes(values: &[F128]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 16);
    for f in values {
        bytes.extend_from_slice(&f.lo.to_le_bytes());
        bytes.extend_from_slice(&f.hi.to_le_bytes());
    }
    bytes
}

/// Canonical low-coordinate-then-high-coordinate encoding used for C1 FRI
/// leaves. Each coordinate retains the established little-endian F128 lane
/// encoding.
fn f256_slice_to_bytes(values: &[F256]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 32);
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Borrow the canonical C1 byte layout without a second codeword-sized copy.
/// F128/F256 are repr(C) little-endian lane structs and all supported targets
/// are little-endian, matching [`f256_slice_to_bytes`] exactly.
fn f256_slice_as_bytes(values: &[F256]) -> &[u8] {
    debug_assert!(cfg!(target_endian = "little"));
    // SAFETY: F256 is repr(C), Copy, contains exactly two repr(C) F128
    // coordinates, and the returned byte slice cannot outlive `values`.
    unsafe {
        core::slice::from_raw_parts(values.as_ptr().cast::<u8>(), std::mem::size_of_val(values))
    }
}

#[inline]
fn fold_pair_c1(twiddle: F128, u_in: F256, v_in: F256, challenge: F256) -> F256 {
    let v = v_in + u_in;
    let u = u_in + v.scale_base(twiddle);
    u + challenge * (u + v)
}

#[inline]
fn fold_pair_base_to_c1(twiddle: F128, u_in: F128, v_in: F128, challenge: F256) -> F256 {
    let v = v_in + u_in;
    let u = u_in + v * twiddle;
    F256::from_base(u) + challenge.scale_base(u + v)
}

fn row_batch_fold_all_c1(codeword: &[F128], out: &mut [F256], challenges: &[F256]) -> usize {
    use rayon::prelude::*;

    let num_ntts = 1usize << challenges.len();
    debug_assert_eq!(codeword.len() % num_ntts, 0);
    let n_positions = codeword.len() / num_ntts;
    const CHUNK: usize = 256;
    out[..n_positions]
        .par_chunks_mut(CHUNK)
        .enumerate()
        .for_each(|(chunk_index, output_chunk)| {
            let mut buffer = vec![F256::ZERO; num_ntts];
            for (offset, output) in output_chunk.iter_mut().enumerate() {
                let base = (chunk_index * CHUNK + offset) * num_ntts;
                for (slot, &value) in buffer.iter_mut().zip(&codeword[base..base + num_ntts]) {
                    *slot = F256::from_base(value);
                }
                let mut length = num_ntts;
                for &challenge in challenges {
                    let half = length / 2;
                    for index in 0..half {
                        let low = buffer[2 * index];
                        let high = buffer[2 * index + 1];
                        buffer[index] = low + challenge * (low + high);
                    }
                    length = half;
                }
                *output = buffer[0];
            }
        });
    n_positions
}

fn row_batch_fold_one_c1(lanes: &[F128], challenges: &[F256]) -> F256 {
    let mut buffer = lanes
        .iter()
        .copied()
        .map(F256::from_base)
        .collect::<Vec<_>>();
    for &challenge in challenges {
        let half = buffer.len() / 2;
        for index in 0..half {
            let low = buffer[2 * index];
            let high = buffer[2 * index + 1];
            buffer[index] = low + challenge * (low + high);
        }
        buffer.truncate(half);
    }
    debug_assert_eq!(buffer.len(), 1);
    buffer[0]
}

fn fri_fold_codeword_c1(
    codeword: &[F256],
    out: &mut [F256],
    ntt: &AdditiveNttF128,
    layer: usize,
    challenge: F256,
) -> usize {
    use rayon::prelude::*;

    let new_len = codeword.len() / 2;
    out[..new_len]
        .par_iter_mut()
        .enumerate()
        .for_each(|(index, output)| {
            *output = fold_pair_c1(
                ntt.twiddle(layer, index),
                codeword[2 * index],
                codeword[2 * index + 1],
                challenge,
            );
        });
    new_len
}

fn fri_fold_coset_c1(
    coset: &[F256],
    challenges: &[F256],
    ntt: &AdditiveNttF128,
    input_layer: usize,
    coset_index: usize,
) -> F256 {
    debug_assert_eq!(coset.len(), 1usize << challenges.len());
    let mut buffer = coset.to_vec();
    for (round, &challenge) in challenges.iter().enumerate() {
        let post_fold_layer = input_layer - round - 1;
        let next_len = buffer.len() / 2;
        for index in 0..next_len {
            let position = coset_index * next_len + index;
            buffer[index] = fold_pair_c1(
                ntt.twiddle(post_fold_layer, position),
                buffer[2 * index],
                buffer[2 * index + 1],
                challenge,
            );
        }
        buffer.truncate(next_len);
    }
    debug_assert_eq!(buffer.len(), 1);
    buffer[0]
}

/// Absorb a 32-byte commitment root into the transcript as two flat lanes
/// (the digest's LE halves). Full-digest binding: anything less would leave
/// an equivocation window on the roots that anchor every FRI query — a
/// half-bound root admits 2^128 sibling digests sharing its bound half.
fn observe_root<Ch: Challenger>(challenger: &mut Ch, root: &Hash) {
    challenger.observe_f128(F128 {
        lo: u64::from_le_bytes(root[0..8].try_into().unwrap()),
        hi: u64::from_le_bytes(root[8..16].try_into().unwrap()),
    });
    challenger.observe_f128(F128 {
        lo: u64::from_le_bytes(root[16..24].try_into().unwrap()),
        hi: u64::from_le_bytes(root[24..32].try_into().unwrap()),
    });
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

pub fn prove<Ch: Challenger>(
    a_init: &[F128],
    b: Vec<F128>,
    target: F128,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    challenger: &mut Ch,
) -> BaseFoldProof {
    prove_with_node_hash(
        a_init,
        b,
        target,
        initial_codeword,
        initial_tree,
        ntt,
        log_inv_rate,
        log_batch_size,
        n_queries,
        challenger,
        ProofNodeHashVersion::FeedForward,
    )
}

pub fn prove_with_node_hash<Ch: Challenger>(
    a_init: &[F128],
    b: Vec<F128>,
    target: F128,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    challenger: &mut Ch,
    node_hash_version: ProofNodeHashVersion,
) -> BaseFoldProof {
    prove_with_precomputed_round0_prime_with_node_hash(
        a_init,
        b,
        target,
        initial_codeword,
        initial_tree,
        ntt,
        log_inv_rate,
        log_batch_size,
        n_queries,
        None,
        challenger,
        node_hash_version,
    )
}

/// Variant of [`prove`] that accepts an optional pre-computed round-0
/// sumcheck message `(u_0, u_2)`. When `Some`, basefold skips its own
/// round-0 prime computation — the caller fused it with the caller
/// b_combined construction (see `pcs::open_batch_mixed`'s fused
/// combine + prime path).
#[allow(clippy::too_many_arguments)]
pub fn prove_with_precomputed_round0_prime<Ch: Challenger>(
    a_init: &[F128],
    b: Vec<F128>,
    target: F128,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    precomputed_round0_prime: Option<(F128, F128)>,
    challenger: &mut Ch,
) -> BaseFoldProof {
    prove_with_precomputed_round0_prime_with_node_hash(
        a_init,
        b,
        target,
        initial_codeword,
        initial_tree,
        ntt,
        log_inv_rate,
        log_batch_size,
        n_queries,
        precomputed_round0_prime,
        challenger,
        ProofNodeHashVersion::FeedForward,
    )
}

pub fn prove_with_precomputed_round0_prime_with_node_hash<Ch: Challenger>(
    a_init: &[F128],
    mut b: Vec<F128>,
    target: F128,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    precomputed_round0_prime: Option<(F128, F128)>,
    challenger: &mut Ch,
    node_hash_version: ProofNodeHashVersion,
) -> BaseFoldProof {
    assert_eq!(a_init.len(), b.len());
    assert!(a_init.len().is_power_of_two() && !a_init.is_empty());
    let log_msg_len = a_init.len().trailing_zeros() as usize;
    assert!(log_batch_size <= log_msg_len);
    let log_dim = log_msg_len - log_batch_size;
    let k_code = log_dim + log_inv_rate;
    let num_ntts = 1usize << log_batch_size;
    assert_eq!(initial_codeword.len(), (1 << k_code) * num_ntts);

    challenger.observe_label(b"history-basefold-v0");

    let arities = crate::pcs::compute_fri_arities(log_dim);
    debug_assert_eq!(arities.iter().sum::<usize>(), log_dim);
    let (num_fri_commits, tail_layout) = fri_commit_layout(k_code, &arities);
    let mut plaintext_tail: Vec<F128> = Vec::new();

    let mut running_target = target;
    let mut round_messages = Vec::with_capacity(log_msg_len);
    let mut round_commitments = Vec::with_capacity(num_fri_commits);
    // Row-batch challenges (r_0..r_{log_batch_size-1}) are collected across the
    // row-batch rounds and applied in a single fused fold after the last one,
    // rather than folding the codeword once per round (≈3× less traffic).
    let mut rb_challenges: Vec<F128> = Vec::with_capacity(log_batch_size);
    // The post-row-batch tree (T2) is built right after the row-batch rounds.
    // Multi-arity leaves of size 2^arity_0 give the first FRI epoch its
    // single-Merkle-open-per-query property.
    let arity_0 = arities.first().copied().unwrap_or(0);
    let post_row_batch_leaf_f128 = 1usize << arity_0;
    let mut post_row_batch_codeword: Vec<F128> = Vec::new();
    let mut post_row_batch_tree: Vec<Hash> = Vec::new();
    let mut post_row_batch_commit_root: Hash = [0u8; 32];

    // Ping-pong working buffers. Backing memory is uninitialized — basefold
    // writes to every slot before reading from it (par_iter_mut populates
    // *_scratch in round 0 from borrowed `a_init`/`initial_codeword`, then
    // mem::swap promotes scratch → active for subsequent rounds). Skipping
    // the zero-init saves ~47 ms (≈320 MB streaming write) at m=29.
    let t_alloc = std::time::Instant::now();
    let mut a_active: Vec<F128> = crate::scratch::take_f128(a_init.len());
    let mut a_scratch: Vec<F128> = crate::scratch::take_f128(a_init.len());
    let mut a_len = a_init.len();
    let mut b_scratch: Vec<F128> = crate::scratch::take_f128(b.len());
    let mut b_len = b.len();
    // The ping-pong codeword buffers only ever hold POST-row-batch data: the
    // row-batch fold reads the borrowed `initial_codeword` and writes at most
    // `n_positions = 2^k_code` elements, and every FRI round shrinks from
    // there. Sizing them at `initial_codeword.len() = n_positions * num_ntts`
    // over-allocates by `num_ntts` (32x at log_batch_size=5 — ~2 GB of unused
    // codeword buffer at the block-bearing class). Size to `n_positions`; when
    // log_batch_size == 0 this equals `initial_codeword.len()` (the FRI-from-
    // round-0 path reads `initial_codeword` directly), so that case is
    // unaffected. The row-batch rounds (round < log_batch_size) never index
    // these buffers before `row_batch_fold_all` resets `cw_len`.
    let n_positions = 1usize << k_code;
    let mut codeword_active: Vec<F128> = crate::scratch::take_f128(n_positions);
    let mut codeword_scratch: Vec<F128> = crate::scratch::take_f128(n_positions);
    let mut cw_len = n_positions;
    let mut current_lanes = num_ntts;
    let upfront_alloc_ms = t_alloc.elapsed().as_secs_f64() * 1e3;

    // Per-FRI-commit storage for query opening: the committed codeword + tree
    // + leaf size (in F_{2^128} elements).
    let mut epoch_codewords: Vec<Vec<F128>> = Vec::with_capacity(num_fri_commits);
    let mut epoch_trees: Vec<Vec<Hash>> = Vec::with_capacity(num_fri_commits);
    let mut epoch_leaf_f128s: Vec<usize> = Vec::with_capacity(num_fri_commits);

    use rayon::prelude::*;

    // Track FRI epoch progress.
    let mut current_epoch = 0usize;
    let mut rounds_in_epoch = 0usize;

    // PCS_TRACE per-phase timing (aggregated across all rounds). Each `_ms`
    // accumulates wall time spent in that phase.
    let trace = std::env::var("PCS_TRACE").is_ok();
    let mut sumcheck_msg_ms = 0.0f64;
    let mut fold_ab_ms = 0.0f64;
    let mut row_batch_fold_ms = 0.0f64;
    let mut fri_fold_ms = 0.0f64;
    let mut post_row_batch_merkle_ms = 0.0f64;
    let mut epoch_merkle_ms = 0.0f64;

    // Prime round 0's sumcheck message from the (unfolded) inputs. Every later
    // round's message is then produced *fused* with that round's (a, b) fold:
    // folding at r_round writes exactly the operands round+1's message reads,
    // so a/b are streamed once per round instead of twice (a separate message
    // pass + a separate fold pass). The message value depends only on r_round,
    // so computing it early but observing it at the top of the next iteration
    // (after this round's Merkle-root observation) keeps the transcript — and
    // thus the proof — byte-identical.
    //
    // When `precomputed_round0_prime` is Some, the caller (pcs combine) fused
    // this with the b_combined materialization caller — skip the redundant
    // pass.
    let t = std::time::Instant::now();
    let (mut cur_u0, mut cur_u2) = if let Some((u_0, u_2)) = precomputed_round0_prime {
        (u_0, u_2)
    } else {
        (0..b_len / 2)
            .into_par_iter()
            .map(|i| {
                let a0 = a_init[2 * i];
                let a1 = a_init[2 * i + 1];
                let b0 = b[2 * i];
                let b1 = b[2 * i + 1];
                (a0 * b0, (a0 + a1) * (b0 + b1))
            })
            .reduce(
                || (F128::ZERO, F128::ZERO),
                |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2),
            )
    };
    if trace {
        sumcheck_msg_ms += t.elapsed().as_secs_f64() * 1e3;
    }

    for round in 0..log_msg_len {
        let half = a_len / 2;

        // For round 0, read directly from the borrowed inputs (no clone). For
        // subsequent rounds, read from the active working buffer.
        let a_src: &[F128] = if round == 0 {
            a_init
        } else {
            &a_active[..a_len]
        };
        let b_src: &[F128] = &b[..b_len];

        // --- Observe this round's message (primed for round 0, otherwise
        // computed fused with the previous round's fold) and derive r.
        let u_0 = cur_u0;
        let u_2 = cur_u2;
        challenger.observe_f128(u_0);
        challenger.observe_f128(u_2);
        round_messages.push(RoundMessage { u_0, u_2 });

        let r = challenger.sample_f128();
        let u_1 = running_target + u_2;
        running_target = u_0 + r * u_1 + r * r * u_2;

        // --- Fused fold-at-r + next round's message. Each output *pair*
        // (a'[2j], a'[2j+1]) is folded from a_src[4j..4j+4] in one read, and
        // that pair's contribution to round+1's (u_0, u_2) is accumulated in
        // the same pass. The final round (half == 1) has no next message, so
        // it folds the lone pair directly.
        let t = std::time::Instant::now();
        if half >= 2 {
            let (n0, n2) = a_scratch[..half]
                .par_chunks_mut(2)
                .zip(b_scratch[..half].par_chunks_mut(2))
                .enumerate()
                .map(|(j, (a_out, b_out))| {
                    let base = 4 * j;
                    let a0 = a_src[base];
                    let a1 = a_src[base + 1];
                    let a2 = a_src[base + 2];
                    let a3 = a_src[base + 3];
                    let b0 = b_src[base];
                    let b1 = b_src[base + 1];
                    let b2 = b_src[base + 2];
                    let b3 = b_src[base + 3];
                    let af0 = a0 + r * (a0 + a1);
                    let af1 = a2 + r * (a2 + a3);
                    let bf0 = b0 + r * (b0 + b1);
                    let bf1 = b2 + r * (b2 + b3);
                    a_out[0] = af0;
                    a_out[1] = af1;
                    b_out[0] = bf0;
                    b_out[1] = bf1;
                    (af0 * bf0, (af0 + af1) * (bf0 + bf1))
                })
                .reduce(
                    || (F128::ZERO, F128::ZERO),
                    |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2),
                );
            cur_u0 = n0;
            cur_u2 = n2;
        } else {
            a_scratch[0] = a_src[0] + r * (a_src[0] + a_src[1]);
            b_scratch[0] = b_src[0] + r * (b_src[0] + b_src[1]);
        }
        std::mem::swap(&mut a_active, &mut a_scratch);
        std::mem::swap(&mut b, &mut b_scratch);
        a_len = half;
        b_len = half;
        if trace {
            fold_ab_ms += t.elapsed().as_secs_f64() * 1e3;
        }

        // --- Codeword fold.
        if round < log_batch_size {
            // Deferred row-batch: just record this round's challenge. The
            // codeword is folded once — all `log_batch_size` lanes at a time —
            // after the final row-batch round, so it is streamed through memory
            // once instead of once per round. The per-round folds touch no
            // transcript state (only the post-row-batch T2 root below does), so
            // deferring leaves the proof byte-identical.
            rb_challenges.push(r);
            if round + 1 == log_batch_size {
                let t = std::time::Instant::now();
                cw_len =
                    row_batch_fold_all(initial_codeword, &mut codeword_scratch, &rb_challenges);
                std::mem::swap(&mut codeword_active, &mut codeword_scratch);
                current_lanes = 1;
                if trace {
                    row_batch_fold_ms += t.elapsed().as_secs_f64() * 1e3;
                }

                // Build T2 over the post-row-batch codeword and observe its root.
                if !arities.is_empty() {
                    let t = std::time::Instant::now();
                    let cw_bytes: &[u8] = unsafe {
                        core::slice::from_raw_parts(
                            codeword_active.as_ptr() as *const u8,
                            cw_len * core::mem::size_of::<F128>(),
                        )
                    };
                    let n_leaves = cw_len / post_row_batch_leaf_f128;
                    post_row_batch_tree =
                        merkle::merkle_tree_with_version(cw_bytes, n_leaves, node_hash_version);
                    post_row_batch_commit_root = *post_row_batch_tree.last().expect("non-empty");
                    observe_root(challenger, &post_row_batch_commit_root);
                    post_row_batch_codeword = codeword_active[..cw_len].to_vec();
                    if trace {
                        post_row_batch_merkle_ms += t.elapsed().as_secs_f64() * 1e3;
                    }
                }
            }
        } else {
            // Round 0 reaches this branch only when log_batch_size == 0, in
            // which case it reads the (unfolded) initial codeword directly.
            let cw_src: &[F128] = if round == 0 {
                initial_codeword
            } else {
                &codeword_active[..cw_len]
            };
            debug_assert_eq!(current_lanes, 1);
            let t = std::time::Instant::now();
            let fri_round_idx = round - log_batch_size;
            let layer = k_code - fri_round_idx - 1;
            cw_len = fri_fold_codeword(cw_src, &mut codeword_scratch, ntt, layer, r);
            std::mem::swap(&mut codeword_active, &mut codeword_scratch);
            if trace {
                fri_fold_ms += t.elapsed().as_secs_f64() * 1e3;
            }

            rounds_in_epoch += 1;

            // Epoch boundary? Boundary b = current_epoch + 1 (the layer
            // entering epoch b): the first `num_fri_commits` boundaries get
            // Merkle commitments; the plaintext-tail boundary absorbs its
            // whole layer instead; anything past the tail commits nothing
            // (the verifier folds the tail locally).
            if rounds_in_epoch == arities[current_epoch] {
                let boundary = current_epoch + 1;
                if boundary <= num_fri_commits {
                    let t = std::time::Instant::now();
                    let next_arity = arities[boundary];
                    let leaf_f128 = 1usize << next_arity;
                    let n_leaves = cw_len / leaf_f128;
                    let cw_bytes: &[u8] = unsafe {
                        core::slice::from_raw_parts(
                            codeword_active.as_ptr() as *const u8,
                            cw_len * core::mem::size_of::<F128>(),
                        )
                    };
                    let tree =
                        merkle::merkle_tree_with_version(cw_bytes, n_leaves, node_hash_version);
                    let root = *tree.last().unwrap();
                    observe_root(challenger, &root);
                    round_commitments.push(RoundCommitment { root });
                    epoch_codewords.push(codeword_active[..cw_len].to_vec());
                    epoch_trees.push(tree);
                    epoch_leaf_f128s.push(leaf_f128);
                    if trace {
                        epoch_merkle_ms += t.elapsed().as_secs_f64() * 1e3;
                    }
                } else if let Some((tail_len, _)) = tail_layout
                    && boundary == num_fri_commits + 1
                {
                    debug_assert_eq!(cw_len, tail_len);
                    for &v in &codeword_active[..cw_len] {
                        challenger.observe_f128(v);
                    }
                    plaintext_tail = codeword_active[..cw_len].to_vec();
                }
                rounds_in_epoch = 0;
                current_epoch += 1;
            }
        }
    }

    debug_assert_eq!(a_len, 1);
    debug_assert_eq!(b_len, 1);
    let final_a = a_active[0];
    let final_b = b[0];
    let final_codeword = codeword_active[..cw_len].to_vec();

    // --- Grind, then sample query positions and gather per-tree leaf
    // indices. The grind pins down the transcript state the positions are
    // drawn from; its soundness contribution is priced into the query table.
    let t_queries = std::time::Instant::now();
    let pow_nonce = challenger.grind_pow(QUERY_GRIND_BITS);
    let mut queries = Vec::with_capacity(n_queries);
    let initial_leaf_f128 = num_ntts;
    let n_initial_leaves = initial_codeword.len() / initial_leaf_f128;

    for position in sample_query_positions(challenger, n_queries, k_code) {
        // T1 leaf (= position) with its own full-depth path.
        let initial_start = position * initial_leaf_f128;
        let initial_leaf =
            initial_codeword[initial_start..initial_start + initial_leaf_f128].to_vec();
        let initial_path = merkle::merkle_proof(initial_tree, n_initial_leaves, position);

        // T2 leaf (multi-arity coset of arity_0 consecutive positions).
        let (post_row_batch_leaf, post_row_batch_path) = if arities.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let leaf_idx = position >> arity_0;
            let start = leaf_idx * post_row_batch_leaf_f128;
            let n_leaves = post_row_batch_codeword.len() / post_row_batch_leaf_f128;
            (
                post_row_batch_codeword[start..start + post_row_batch_leaf_f128].to_vec(),
                merkle::merkle_proof(&post_row_batch_tree, n_leaves, leaf_idx),
            )
        };

        // Per-epoch leaves with their paths.
        let mut epoch_leaves = Vec::with_capacity(num_fri_commits);
        let mut epoch_paths = Vec::with_capacity(num_fri_commits);
        let mut cum_arity = arity_0;
        for i in 0..num_fri_commits {
            let p_next = position >> cum_arity;
            let leaf_f128 = epoch_leaf_f128s[i];
            let leaf_idx = p_next / leaf_f128;
            let start = leaf_idx * leaf_f128;
            let n_leaves = epoch_codewords[i].len() / leaf_f128;
            epoch_leaves.push(epoch_codewords[i][start..start + leaf_f128].to_vec());
            epoch_paths.push(merkle::merkle_proof(&epoch_trees[i], n_leaves, leaf_idx));
            cum_arity += arities[i + 1];
        }

        queries.push(QueryOpening {
            position,
            initial_leaf,
            initial_path,
            post_row_batch_leaf,
            post_row_batch_path,
            epoch_leaves,
            epoch_paths,
        });
    }
    let query_openings_ms = t_queries.elapsed().as_secs_f64() * 1e3;

    if trace {
        let total = upfront_alloc_ms
            + sumcheck_msg_ms
            + fold_ab_ms
            + row_batch_fold_ms
            + fri_fold_ms
            + post_row_batch_merkle_ms
            + epoch_merkle_ms
            + query_openings_ms;
        eprintln!(
            "  [basefold::prove] upfront ping-pong vec alloc:        {:6.2} ms",
            upfront_alloc_ms
        );
        eprintln!(
            "  [basefold::prove] sumcheck msg (round-0 prime only):  {:6.2} ms",
            sumcheck_msg_ms
        );
        eprintln!(
            "  [basefold::prove] fused fold+msg (all rounds):        {:6.2} ms",
            fold_ab_ms
        );
        eprintln!(
            "  [basefold::prove] row_batch_fold (rounds < {}):       {:6.2} ms",
            log_batch_size, row_batch_fold_ms
        );
        eprintln!(
            "  [basefold::prove] post-row-batch merkle (one-time):   {:6.2} ms",
            post_row_batch_merkle_ms
        );
        eprintln!(
            "  [basefold::prove] fri_fold_codeword (all FRI rounds): {:6.2} ms",
            fri_fold_ms
        );
        eprintln!(
            "  [basefold::prove] epoch merkle commits ({} epochs):    {:6.2} ms",
            num_fri_commits, epoch_merkle_ms
        );
        eprintln!(
            "  [basefold::prove] query openings ({} queries):       {:6.2} ms",
            n_queries, query_openings_ms
        );
        eprintln!(
            "  [basefold::prove] traced sum:                          {:6.2} ms",
            total
        );
    }

    // Recycle every large transient through the scratch pool. Leaving these
    // to malloc while the early-phase buffers sit in the pool would force
    // fresh page faults here each prove (see scratch.rs docs).
    crate::scratch::give_f128(a_active);
    crate::scratch::give_f128(a_scratch);
    crate::scratch::give_f128(b);
    crate::scratch::give_f128(b_scratch);
    crate::scratch::give_f128(codeword_active);
    crate::scratch::give_f128(codeword_scratch);
    crate::scratch::give_f128(post_row_batch_codeword);
    for cw in epoch_codewords {
        crate::scratch::give_f128(cw);
    }

    BaseFoldProof {
        round_messages,
        post_row_batch_commit: RoundCommitment {
            root: post_row_batch_commit_root,
        },
        round_commitments,
        final_a,
        final_b,
        final_codeword,
        plaintext_tail,
        pow_nonce,
        queries,
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// BaseFold verifier. Replays sumcheck + multi-arity FRI consistency and
/// returns the per-round sumcheck challenges so the caller (PCS) can compute
/// `final_b = b(challenges)` and match it against `proof.final_b`.
pub fn verify<Ch: Challenger>(
    target: F128,
    proof: &BaseFoldProof,
    initial_codeword_root: &Hash,
    ntt: &AdditiveNttF128,
    log_msg_len: usize,
    log_inv_rate: usize,
    log_batch_size: usize,
    challenger: &mut Ch,
) -> Result<Vec<F128>, VerifyError> {
    verify_with_node_hash(
        target,
        proof,
        initial_codeword_root,
        ntt,
        log_msg_len,
        log_inv_rate,
        log_batch_size,
        challenger,
        ProofNodeHashVersion::FeedForward,
    )
}

pub fn verify_with_node_hash<Ch: Challenger>(
    target: F128,
    proof: &BaseFoldProof,
    initial_codeword_root: &Hash,
    ntt: &AdditiveNttF128,
    log_msg_len: usize,
    log_inv_rate: usize,
    log_batch_size: usize,
    challenger: &mut Ch,
    node_hash_version: ProofNodeHashVersion,
) -> Result<Vec<F128>, VerifyError> {
    // SECURITY: the sumcheck depth is a commitment parameter, not a prover
    // choice. Deriving it from the proof would let adversarial bytes select
    // every downstream shape (epoch arities, codeword sizes, query masks,
    // challenge-vector length) and reach release-mode panics in the caller
    // before any binding check fires. Hard-reject a mismatched proof.
    if proof.round_messages.len() != log_msg_len {
        return Err(VerifyError::InvalidProofShape);
    }
    if log_batch_size > log_msg_len {
        return Err(VerifyError::InvalidProofShape);
    }
    let log_dim = log_msg_len - log_batch_size;
    let k_code = log_dim + log_inv_rate;
    let num_ntts = 1usize << log_batch_size;
    let arities = crate::pcs::compute_fri_arities(log_dim);
    let (num_fri_commits, tail_layout) = fri_commit_layout(k_code, &arities);

    challenger.observe_label(b"history-basefold-v0");

    if proof.round_commitments.len() != num_fri_commits {
        return Err(VerifyError::InvalidProofShape);
    }
    if proof.plaintext_tail.len() != tail_layout.map_or(0, |(len, _)| len) {
        return Err(VerifyError::InvalidProofShape);
    }

    // SECURITY: the number of FRI queries is a soundness parameter, not a
    // prover choice. A malicious prover that sends fewer queries (down to
    // zero) strips the codeword-to-commitment binding and can prove a false
    // evaluation. Enforce the finite domain-and-rate-derived count before
    // sampling positions.
    if proof.queries.len() != default_fri_queries(log_dim, log_inv_rate) {
        return Err(VerifyError::InvalidProofShape);
    }

    let mut running_target = target;
    let mut challenges = Vec::with_capacity(log_msg_len);

    let mut current_epoch = 0usize;
    let mut rounds_in_epoch = 0usize;

    // Replay sumcheck rounds in lockstep with prover; observe T2 (post-row-
    // batch) commit right after the last row-batch round; observe FRI epoch-
    // boundary commits as before.
    for round in 0..log_msg_len {
        let msg = &proof.round_messages[round];
        challenger.observe_f128(msg.u_0);
        challenger.observe_f128(msg.u_2);
        let r = challenger.sample_f128();
        challenges.push(r);

        let u_1 = running_target + msg.u_2;
        running_target = msg.u_0 + r * u_1 + r * r * msg.u_2;

        if round + 1 == log_batch_size && !arities.is_empty() {
            observe_root(challenger, &proof.post_row_batch_commit.root);
        }

        if round >= log_batch_size {
            rounds_in_epoch += 1;
            if rounds_in_epoch == arities[current_epoch] {
                let boundary = current_epoch + 1;
                if boundary <= num_fri_commits {
                    let root = proof.round_commitments[current_epoch].root;
                    observe_root(challenger, &root);
                } else if tail_layout.is_some() && boundary == num_fri_commits + 1 {
                    // The plaintext-tail layer replaces this boundary's
                    // commitment: absorb it whole (proof data), binding the
                    // query positions drawn below to it.
                    for &v in &proof.plaintext_tail {
                        challenger.observe_f128(v);
                    }
                }
                rounds_in_epoch = 0;
                current_epoch += 1;
            }
        }
    }

    // Final sumcheck consistency.
    if proof.final_a * proof.final_b != running_target {
        return Err(VerifyError::SumcheckFinalMismatch);
    }

    // Final codeword constancy + equality with final_a.
    if proof.final_codeword.len() != 1 << log_inv_rate {
        return Err(VerifyError::FinalCodewordNotConstant);
    }
    let constant = proof.final_codeword[0];
    for &v in proof.final_codeword.iter().skip(1) {
        if v != constant {
            return Err(VerifyError::FinalCodewordNotConstant);
        }
    }
    if constant != proof.final_a {
        return Err(VerifyError::SumcheckFriMismatch);
    }

    // Check the pre-query transcript grinding, then resample query
    // positions (challenger state matches prover).
    if !challenger.verify_pow(proof.pow_nonce, QUERY_GRIND_BITS) {
        return Err(VerifyError::GrindingFailed);
    }
    let n_queries = proof.queries.len();
    let positions = sample_query_positions(challenger, n_queries, k_code);

    let arity_0 = arities.first().copied().unwrap_or(0);
    let initial_leaf_f128 = num_ntts; // T1: one position's row-batch lanes
    let post_row_batch_leaf_f128 = 1usize << arity_0;

    for (qi, q) in proof.queries.iter().enumerate() {
        if q.position != positions[qi] {
            return Err(VerifyError::FoldMismatch {
                query_index: qi,
                epoch: 0,
            });
        }
        if q.initial_leaf.len() != initial_leaf_f128 {
            return Err(VerifyError::InitialMerkleFailed { query_index: qi });
        }
        if q.epoch_leaves.len() != num_fri_commits || q.epoch_paths.len() != num_fri_commits {
            return Err(VerifyError::InvalidProofShape);
        }

        // T1: hash the initial leaf and verify its own full-depth path. The
        // path length IS the tree depth — a shorter path would prove
        // membership against an inner node, so it is shape-checked exactly.
        if q.initial_path.len() != k_code {
            return Err(VerifyError::InvalidProofShape);
        }
        let initial_leaf_hash = merkle::hash_leaf(&f128_slice_to_bytes(&q.initial_leaf));
        if !merkle::verify_merkle_proof_with_version(
            initial_codeword_root,
            &initial_leaf_hash,
            q.position,
            &q.initial_path,
            node_hash_version,
        ) {
            return Err(VerifyError::InitialMerkleFailed { query_index: qi });
        }

        // Row-batch fold T1's lanes to a single post-row-batch F_{2^128}.
        let post_row_batch_value =
            row_batch_fold_one(&q.initial_leaf, &challenges[..log_batch_size]);

        // T2: cross-check the post-row-batch leaf; Merkle path verified in batch.
        let mut expected;
        let fri_challenge_start = log_batch_size;
        let mut cum_arity = arity_0;
        if arities.is_empty() {
            // log_dim = 0: no FRI rounds; the post-row-batch value IS the
            // final fold output.
            expected = post_row_batch_value;
        } else {
            if q.post_row_batch_leaf.len() != post_row_batch_leaf_f128 {
                return Err(VerifyError::InvalidProofShape);
            }
            if q.post_row_batch_path.len() != k_code - arity_0 {
                return Err(VerifyError::InvalidProofShape);
            }
            let post_leaf_idx = q.position >> arity_0;
            let post_leaf_hash = merkle::hash_leaf(&f128_slice_to_bytes(&q.post_row_batch_leaf));
            if !merkle::verify_merkle_proof_with_version(
                &proof.post_row_batch_commit.root,
                &post_leaf_hash,
                post_leaf_idx,
                &q.post_row_batch_path,
                node_hash_version,
            ) {
                return Err(VerifyError::InitialMerkleFailed { query_index: qi });
            }

            // Cross-check: T2 at the queried offset within its leaf must equal
            // the row-batch fold of T1.
            let inner_offset = q.position & ((1usize << arity_0) - 1);
            if q.post_row_batch_leaf[inner_offset] != post_row_batch_value {
                return Err(VerifyError::FoldMismatch {
                    query_index: qi,
                    epoch: 0,
                });
            }

            // FRI fold T2's 2^arity_0 values via the first arity_0 FRI challenges.
            let coset_idx_in_layer = q.position >> arity_0;
            expected = fri_fold_coset(
                &q.post_row_batch_leaf,
                &challenges[fri_challenge_start..fri_challenge_start + arity_0],
                ntt,
                k_code,
                coset_idx_in_layer,
            );
        }

        // Walk through FRI commits.
        for i in 0..num_fri_commits {
            let leaf = &q.epoch_leaves[i];
            let next_arity = arities[i + 1];
            if leaf.len() != 1usize << next_arity {
                return Err(VerifyError::InvalidProofShape);
            }
            let p_at_this_layer = q.position >> cum_arity;
            let leaf_idx = p_at_this_layer >> next_arity;
            let offset = p_at_this_layer & ((1usize << next_arity) - 1);

            if q.epoch_paths[i].len() != k_code - cum_arity - next_arity {
                return Err(VerifyError::InvalidProofShape);
            }
            let epoch_leaf_hash = merkle::hash_leaf(&f128_slice_to_bytes(leaf));
            if !merkle::verify_merkle_proof_with_version(
                &proof.round_commitments[i].root,
                &epoch_leaf_hash,
                leaf_idx,
                &q.epoch_paths[i],
                node_hash_version,
            ) {
                return Err(VerifyError::RoundMerkleFailed {
                    query_index: qi,
                    epoch: i,
                });
            }

            // Check the leaf carries the expected value at the relevant offset.
            if leaf[offset] != expected {
                return Err(VerifyError::FoldMismatch {
                    query_index: qi,
                    epoch: i,
                });
            }

            // FRI fold the leaf (2^next_arity values) via next_arity challenges.
            let input_layer = k_code - cum_arity;
            let next_coset_idx = leaf_idx;
            expected = fri_fold_coset(
                leaf,
                &challenges
                    [fri_challenge_start + cum_arity..fri_challenge_start + cum_arity + next_arity],
                ntt,
                input_layer,
                next_coset_idx,
            );
            cum_arity += next_arity;
        }

        // Final check: against the plaintext tail layer when one exists
        // (the tail itself folds to the final codeword once, below), else
        // directly against the plaintext final codeword.
        if let Some((_, tail_cum)) = tail_layout {
            debug_assert_eq!(cum_arity, tail_cum);
            let p_tail = q.position >> cum_arity;
            if proof.plaintext_tail[p_tail] != expected {
                return Err(VerifyError::FoldMismatch {
                    query_index: qi,
                    epoch: num_fri_commits,
                });
            }
        } else {
            let p_final = q.position >> cum_arity;
            if proof.final_codeword[p_final] != expected {
                return Err(VerifyError::FoldMismatch {
                    query_index: qi,
                    epoch: num_fri_commits,
                });
            }
        }
    }

    // The plaintext tail must itself fold to the final codeword: each
    // contiguous 2^rem-element coset folds through the remaining FRI
    // challenges to one final-layer element.
    if let Some((tail_len, tail_cum)) = tail_layout {
        let rem = log_dim - tail_cum;
        let coset = 1usize << rem;
        debug_assert_eq!(tail_len >> rem, 1usize << log_inv_rate);
        let fri_challenge_start = log_batch_size;
        let rem_challenges =
            &challenges[fri_challenge_start + tail_cum..fri_challenge_start + log_dim];
        let input_layer = k_code - tail_cum;
        for f in 0..(tail_len >> rem) {
            let folded = fri_fold_coset(
                &proof.plaintext_tail[f * coset..(f + 1) * coset],
                rem_challenges,
                ntt,
                input_layer,
                f,
            );
            if folded != proof.final_codeword[f] {
                return Err(VerifyError::FoldMismatch {
                    query_index: 0,
                    epoch: num_fri_commits,
                });
            }
        }
    }

    Ok(challenges)
}

// ---------------------------------------------------------------------------
// C1 prover and verifier
// ---------------------------------------------------------------------------

/// C1 BaseFold over an F128-valued committed polynomial. The commitment and
/// its T1 openings stay byte-identical to the existing PCS; every algebraic
/// value produced after the commitment is lifted to F256.
#[allow(clippy::too_many_arguments)]
pub fn prove_c1<Ch: Challenger>(
    a_init: &[F128],
    b: Vec<F256>,
    target: F256,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    challenger: &mut Ch,
) -> C1BaseFoldProof {
    prove_c1_with_node_hash(
        a_init,
        b,
        target,
        initial_codeword,
        initial_tree,
        ntt,
        log_inv_rate,
        log_batch_size,
        n_queries,
        challenger,
        ProofNodeHashVersion::FeedForward,
    )
}

pub fn prove_c1_with_node_hash<Ch: Challenger>(
    a_init: &[F128],
    b: Vec<F256>,
    target: F256,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    challenger: &mut Ch,
    node_hash_version: ProofNodeHashVersion,
) -> C1BaseFoldProof {
    prove_c1_with_precomputed_round0_prime_with_node_hash(
        a_init,
        b,
        target,
        initial_codeword,
        initial_tree,
        ntt,
        log_inv_rate,
        log_batch_size,
        n_queries,
        None,
        challenger,
        node_hash_version,
    )
}

/// C1 BaseFold with a round-zero message fused into the caller's construction
/// of the wide transparent tensor.
#[allow(clippy::too_many_arguments)]
pub fn prove_c1_with_precomputed_round0_prime<Ch: Challenger>(
    a_init: &[F128],
    b: Vec<F256>,
    target: F256,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    precomputed_round0_prime: Option<(F256, F256)>,
    challenger: &mut Ch,
) -> C1BaseFoldProof {
    prove_c1_with_precomputed_round0_prime_with_node_hash(
        a_init,
        b,
        target,
        initial_codeword,
        initial_tree,
        ntt,
        log_inv_rate,
        log_batch_size,
        n_queries,
        precomputed_round0_prime,
        challenger,
        ProofNodeHashVersion::FeedForward,
    )
}

pub fn prove_c1_with_precomputed_round0_prime_with_node_hash<Ch: Challenger>(
    a_init: &[F128],
    mut b: Vec<F256>,
    target: F256,
    initial_codeword: &[F128],
    initial_tree: &[Hash],
    ntt: &AdditiveNttF128,
    log_inv_rate: usize,
    log_batch_size: usize,
    n_queries: usize,
    precomputed_round0_prime: Option<(F256, F256)>,
    challenger: &mut Ch,
    node_hash_version: ProofNodeHashVersion,
) -> C1BaseFoldProof {
    use rayon::prelude::*;

    assert_eq!(a_init.len(), b.len());
    assert!(a_init.len().is_power_of_two() && !a_init.is_empty());
    let log_msg_len = a_init.len().trailing_zeros() as usize;
    assert!(log_batch_size <= log_msg_len);
    let log_dim = log_msg_len - log_batch_size;
    let k_code = log_dim + log_inv_rate;
    let num_ntts = 1usize << log_batch_size;
    assert_eq!(initial_codeword.len(), (1usize << k_code) * num_ntts);

    challenger.observe_label(b"history-basefold-c1");

    let arities = crate::pcs::compute_fri_arities(log_dim);
    debug_assert_eq!(arities.iter().sum::<usize>(), log_dim);
    let (num_fri_commits, tail_layout) = fri_commit_layout(k_code, &arities);
    let mut plaintext_tail = Vec::new();
    let mut running_target = target;
    let mut round_messages = Vec::with_capacity(log_msg_len);
    let mut round_commitments = Vec::with_capacity(num_fri_commits);
    let mut row_batch_challenges = Vec::with_capacity(log_batch_size);

    let first_arity = arities.first().copied().unwrap_or(0);
    let post_row_batch_leaf_f256 = 1usize << first_arity;
    let mut post_row_batch_codeword = Vec::new();
    let mut post_row_batch_tree = Vec::new();
    let mut post_row_batch_commit_root = [0u8; 32];

    // Every slot is written before it is read. At the production B255 width
    // these are the dominant C1 transients, so avoid serial zero-fills.
    let mut a_active: Vec<F256> = crate::alloc_uninit_vec(a_init.len());
    let mut a_scratch: Vec<F256> = crate::alloc_uninit_vec(a_init.len());
    let mut a_len = a_init.len();
    let mut b_scratch: Vec<F256> = crate::alloc_uninit_vec(b.len());
    let mut b_len = b.len();
    let n_positions = 1usize << k_code;
    let mut codeword_active: Vec<F256> = crate::alloc_uninit_vec(n_positions);
    let mut codeword_scratch: Vec<F256> = crate::alloc_uninit_vec(n_positions);
    let mut codeword_len = n_positions;

    let mut epoch_codewords: Vec<Vec<F256>> = Vec::with_capacity(num_fri_commits);
    let mut epoch_trees: Vec<Vec<Hash>> = Vec::with_capacity(num_fri_commits);
    let mut epoch_leaf_f256s = Vec::with_capacity(num_fri_commits);

    // With no row-batch rounds, T2 commits to the base codeword lifted into
    // the extension before the first FRI challenge is drawn.
    if log_batch_size == 0 {
        codeword_active
            .par_iter_mut()
            .zip(initial_codeword.par_iter())
            .for_each(|(output, &value)| *output = F256::from_base(value));
        if !arities.is_empty() {
            let leaf_count = codeword_len / post_row_batch_leaf_f256;
            post_row_batch_tree = merkle::merkle_tree_with_version(
                f256_slice_as_bytes(&codeword_active),
                leaf_count,
                node_hash_version,
            );
            post_row_batch_commit_root = *post_row_batch_tree.last().expect("non-empty T2");
            observe_root(challenger, &post_row_batch_commit_root);
            post_row_batch_codeword = codeword_active.clone();
        }
    }

    let (mut current_u0, mut current_u2) = if let Some(message) = precomputed_round0_prime {
        message
    } else {
        (0..b_len / 2)
            .into_par_iter()
            .map(|index| {
                let a0 = a_init[2 * index];
                let a1 = a_init[2 * index + 1];
                let b0 = b[2 * index];
                let b1 = b[2 * index + 1];
                (b0.scale_base(a0), (b0 + b1).scale_base(a0 + a1))
            })
            .reduce(
                || (F256::ZERO, F256::ZERO),
                |left, right| (left.0 + right.0, left.1 + right.1),
            )
    };

    let mut current_epoch = 0usize;
    let mut rounds_in_epoch = 0usize;
    for round in 0..log_msg_len {
        let half = a_len / 2;
        let u_0 = current_u0;
        let u_2 = current_u2;
        challenger.observe_f256(u_0);
        challenger.observe_f256(u_2);
        round_messages.push(C1RoundMessage { u_0, u_2 });

        let challenge = challenger.sample_f256();
        let u_1 = running_target + u_2;
        running_target = u_0 + challenge * u_1 + challenge * challenge * u_2;

        if round == 0 {
            let b_source = &b[..b_len];
            if half >= 2 {
                let (next_u0, next_u2) = a_scratch[..half]
                    .par_chunks_mut(2)
                    .zip(b_scratch[..half].par_chunks_mut(2))
                    .enumerate()
                    .map(|(chunk, (a_output, b_output))| {
                        let base = 4 * chunk;
                        let a0 = a_init[base];
                        let a1 = a_init[base + 1];
                        let a2 = a_init[base + 2];
                        let a3 = a_init[base + 3];
                        let b0 = b_source[base];
                        let b1 = b_source[base + 1];
                        let b2 = b_source[base + 2];
                        let b3 = b_source[base + 3];
                        let a_fold0 = F256::from_base(a0) + challenge.scale_base(a0 + a1);
                        let a_fold1 = F256::from_base(a2) + challenge.scale_base(a2 + a3);
                        let b_fold0 = b0 + challenge * (b0 + b1);
                        let b_fold1 = b2 + challenge * (b2 + b3);
                        a_output[0] = a_fold0;
                        a_output[1] = a_fold1;
                        b_output[0] = b_fold0;
                        b_output[1] = b_fold1;
                        (a_fold0 * b_fold0, (a_fold0 + a_fold1) * (b_fold0 + b_fold1))
                    })
                    .reduce(
                        || (F256::ZERO, F256::ZERO),
                        |left, right| (left.0 + right.0, left.1 + right.1),
                    );
                current_u0 = next_u0;
                current_u2 = next_u2;
            } else {
                a_scratch[0] =
                    F256::from_base(a_init[0]) + challenge.scale_base(a_init[0] + a_init[1]);
                b_scratch[0] = b_source[0] + challenge * (b_source[0] + b_source[1]);
            }
        } else {
            let a_source = &a_active[..a_len];
            let b_source = &b[..b_len];
            if half >= 2 {
                let (next_u0, next_u2) = a_scratch[..half]
                    .par_chunks_mut(2)
                    .zip(b_scratch[..half].par_chunks_mut(2))
                    .enumerate()
                    .map(|(chunk, (a_output, b_output))| {
                        let base = 4 * chunk;
                        let a0 = a_source[base];
                        let a1 = a_source[base + 1];
                        let a2 = a_source[base + 2];
                        let a3 = a_source[base + 3];
                        let b0 = b_source[base];
                        let b1 = b_source[base + 1];
                        let b2 = b_source[base + 2];
                        let b3 = b_source[base + 3];
                        let a_fold0 = a0 + challenge * (a0 + a1);
                        let a_fold1 = a2 + challenge * (a2 + a3);
                        let b_fold0 = b0 + challenge * (b0 + b1);
                        let b_fold1 = b2 + challenge * (b2 + b3);
                        a_output[0] = a_fold0;
                        a_output[1] = a_fold1;
                        b_output[0] = b_fold0;
                        b_output[1] = b_fold1;
                        (a_fold0 * b_fold0, (a_fold0 + a_fold1) * (b_fold0 + b_fold1))
                    })
                    .reduce(
                        || (F256::ZERO, F256::ZERO),
                        |left, right| (left.0 + right.0, left.1 + right.1),
                    );
                current_u0 = next_u0;
                current_u2 = next_u2;
            } else {
                a_scratch[0] = a_source[0] + challenge * (a_source[0] + a_source[1]);
                b_scratch[0] = b_source[0] + challenge * (b_source[0] + b_source[1]);
            }
        }
        std::mem::swap(&mut a_active, &mut a_scratch);
        std::mem::swap(&mut b, &mut b_scratch);
        a_len = half;
        b_len = half;

        if round < log_batch_size {
            row_batch_challenges.push(challenge);
            if round + 1 == log_batch_size {
                codeword_len = row_batch_fold_all_c1(
                    initial_codeword,
                    &mut codeword_scratch,
                    &row_batch_challenges,
                );
                std::mem::swap(&mut codeword_active, &mut codeword_scratch);
                if !arities.is_empty() {
                    let leaf_count = codeword_len / post_row_batch_leaf_f256;
                    post_row_batch_tree = merkle::merkle_tree_with_version(
                        f256_slice_as_bytes(&codeword_active[..codeword_len]),
                        leaf_count,
                        node_hash_version,
                    );
                    post_row_batch_commit_root = *post_row_batch_tree.last().expect("non-empty T2");
                    observe_root(challenger, &post_row_batch_commit_root);
                    post_row_batch_codeword = codeword_active[..codeword_len].to_vec();
                }
            }
        } else {
            let fri_round = round - log_batch_size;
            let layer = k_code - fri_round - 1;
            codeword_len = fri_fold_codeword_c1(
                &codeword_active[..codeword_len],
                &mut codeword_scratch,
                ntt,
                layer,
                challenge,
            );
            std::mem::swap(&mut codeword_active, &mut codeword_scratch);

            rounds_in_epoch += 1;
            if rounds_in_epoch == arities[current_epoch] {
                let boundary = current_epoch + 1;
                if boundary <= num_fri_commits {
                    let next_arity = arities[boundary];
                    let leaf_f256 = 1usize << next_arity;
                    let leaf_count = codeword_len / leaf_f256;
                    let tree = merkle::merkle_tree_with_version(
                        f256_slice_as_bytes(&codeword_active[..codeword_len]),
                        leaf_count,
                        node_hash_version,
                    );
                    let root = *tree.last().expect("non-empty C1 epoch tree");
                    observe_root(challenger, &root);
                    round_commitments.push(RoundCommitment { root });
                    epoch_codewords.push(codeword_active[..codeword_len].to_vec());
                    epoch_trees.push(tree);
                    epoch_leaf_f256s.push(leaf_f256);
                } else if let Some((tail_len, _)) = tail_layout
                    && boundary == num_fri_commits + 1
                {
                    debug_assert_eq!(codeword_len, tail_len);
                    challenger.observe_f256_slice(&codeword_active[..codeword_len]);
                    plaintext_tail = codeword_active[..codeword_len].to_vec();
                }
                rounds_in_epoch = 0;
                current_epoch += 1;
            }
        }
    }

    debug_assert_eq!(a_len, 1);
    debug_assert_eq!(b_len, 1);
    let final_a = a_active[0];
    let final_b = b[0];
    let final_codeword = codeword_active[..codeword_len].to_vec();

    let pow_nonce = challenger.grind_pow(QUERY_GRIND_BITS);
    let mut queries = Vec::with_capacity(n_queries);
    let initial_leaf_f128 = num_ntts;
    let initial_leaf_count = initial_codeword.len() / initial_leaf_f128;
    for position in sample_query_positions(challenger, n_queries, k_code) {
        let initial_start = position * initial_leaf_f128;
        let initial_leaf =
            initial_codeword[initial_start..initial_start + initial_leaf_f128].to_vec();
        let initial_path = merkle::merkle_proof(initial_tree, initial_leaf_count, position);

        let (post_row_batch_leaf, post_row_batch_path) = if arities.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let leaf_index = position >> first_arity;
            let start = leaf_index * post_row_batch_leaf_f256;
            let leaf_count = post_row_batch_codeword.len() / post_row_batch_leaf_f256;
            (
                post_row_batch_codeword[start..start + post_row_batch_leaf_f256].to_vec(),
                merkle::merkle_proof(&post_row_batch_tree, leaf_count, leaf_index),
            )
        };

        let mut epoch_leaves = Vec::with_capacity(num_fri_commits);
        let mut epoch_paths = Vec::with_capacity(num_fri_commits);
        let mut cumulative_arity = first_arity;
        for epoch in 0..num_fri_commits {
            let position_at_epoch = position >> cumulative_arity;
            let leaf_f256 = epoch_leaf_f256s[epoch];
            let leaf_index = position_at_epoch / leaf_f256;
            let start = leaf_index * leaf_f256;
            let leaf_count = epoch_codewords[epoch].len() / leaf_f256;
            epoch_leaves.push(epoch_codewords[epoch][start..start + leaf_f256].to_vec());
            epoch_paths.push(merkle::merkle_proof(
                &epoch_trees[epoch],
                leaf_count,
                leaf_index,
            ));
            cumulative_arity += arities[epoch + 1];
        }

        queries.push(C1QueryOpening {
            position,
            initial_leaf,
            initial_path,
            post_row_batch_leaf,
            post_row_batch_path,
            epoch_leaves,
            epoch_paths,
        });
    }

    C1BaseFoldProof {
        round_messages,
        post_row_batch_commit: RoundCommitment {
            root: post_row_batch_commit_root,
        },
        round_commitments,
        final_a,
        final_b,
        final_codeword,
        plaintext_tail,
        pow_nonce,
        queries,
    }
}

/// Verify C1 BaseFold and return its wide sumcheck/FRI challenges.
#[allow(clippy::too_many_arguments)]
pub fn verify_c1<Ch: Challenger>(
    target: F256,
    proof: &C1BaseFoldProof,
    initial_codeword_root: &Hash,
    ntt: &AdditiveNttF128,
    log_msg_len: usize,
    log_inv_rate: usize,
    log_batch_size: usize,
    challenger: &mut Ch,
) -> Result<Vec<F256>, VerifyError> {
    verify_c1_with_node_hash(
        target,
        proof,
        initial_codeword_root,
        ntt,
        log_msg_len,
        log_inv_rate,
        log_batch_size,
        challenger,
        ProofNodeHashVersion::FeedForward,
    )
}

pub fn verify_c1_with_node_hash<Ch: Challenger>(
    target: F256,
    proof: &C1BaseFoldProof,
    initial_codeword_root: &Hash,
    ntt: &AdditiveNttF128,
    log_msg_len: usize,
    log_inv_rate: usize,
    log_batch_size: usize,
    challenger: &mut Ch,
    node_hash_version: ProofNodeHashVersion,
) -> Result<Vec<F256>, VerifyError> {
    use rayon::prelude::*;

    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    if proof.round_messages.len() != log_msg_len || log_batch_size > log_msg_len {
        return Err(VerifyError::InvalidProofShape);
    }
    let log_dim = log_msg_len - log_batch_size;
    let k_code = log_dim + log_inv_rate;
    let num_ntts = 1usize << log_batch_size;
    let arities = crate::pcs::compute_fri_arities(log_dim);
    let (num_fri_commits, tail_layout) = fri_commit_layout(k_code, &arities);

    challenger.observe_label(b"history-basefold-c1");
    if proof.round_commitments.len() != num_fri_commits
        || proof.plaintext_tail.len() != tail_layout.map_or(0, |layout| layout.0)
        || proof.queries.len() != default_fri_queries(log_dim, log_inv_rate)
    {
        return Err(VerifyError::InvalidProofShape);
    }

    // With no row batching, T2 is transcript-bound before round zero.
    if log_batch_size == 0 && !arities.is_empty() {
        observe_root(challenger, &proof.post_row_batch_commit.root);
    }

    let mut running_target = target;
    let mut challenges = Vec::with_capacity(log_msg_len);
    let mut current_epoch = 0usize;
    let mut rounds_in_epoch = 0usize;
    for round in 0..log_msg_len {
        let message = proof.round_messages[round];
        challenger.observe_f256(message.u_0);
        challenger.observe_f256(message.u_2);
        let challenge = challenger.sample_f256();
        challenges.push(challenge);

        let u_1 = running_target + message.u_2;
        running_target = message.u_0 + challenge * u_1 + challenge * challenge * message.u_2;

        if round + 1 == log_batch_size && !arities.is_empty() {
            observe_root(challenger, &proof.post_row_batch_commit.root);
        }
        if round >= log_batch_size {
            rounds_in_epoch += 1;
            if rounds_in_epoch == arities[current_epoch] {
                let boundary = current_epoch + 1;
                if boundary <= num_fri_commits {
                    observe_root(challenger, &proof.round_commitments[current_epoch].root);
                } else if tail_layout.is_some() && boundary == num_fri_commits + 1 {
                    challenger.observe_f256_slice(&proof.plaintext_tail);
                }
                rounds_in_epoch = 0;
                current_epoch += 1;
            }
        }
    }

    if proof.final_a * proof.final_b != running_target {
        return Err(VerifyError::SumcheckFinalMismatch);
    }
    if proof.final_codeword.len() != 1usize << log_inv_rate {
        return Err(VerifyError::FinalCodewordNotConstant);
    }
    let constant = proof.final_codeword[0];
    if proof.final_codeword.iter().any(|&value| value != constant) {
        return Err(VerifyError::FinalCodewordNotConstant);
    }
    if constant != proof.final_a {
        return Err(VerifyError::SumcheckFriMismatch);
    }

    if !challenger.verify_pow(proof.pow_nonce, QUERY_GRIND_BITS) {
        return Err(VerifyError::GrindingFailed);
    }
    let positions = sample_query_positions(challenger, proof.queries.len(), k_code);
    let first_arity = arities.first().copied().unwrap_or(0);
    let initial_leaf_f128 = num_ntts;
    let post_row_batch_leaf_f256 = 1usize << first_arity;
    let prefix_micros = total_started.elapsed().as_micros();
    let queries_started = std::time::Instant::now();

    // Query positions are transcript-bound above. Every opening can now be
    // checked independently through the node's bounded Rayon pool. Collect
    // indexed results before returning an error so rejection remains ordered
    // by query index even though the work itself is parallel.
    let query_results = proof
        .queries
        .par_iter()
        .enumerate()
        .map(|(query_index, query)| -> Result<(), VerifyError> {
            if query.position != positions[query_index] {
                return Err(VerifyError::FoldMismatch {
                    query_index,
                    epoch: 0,
                });
            }
            if query.initial_leaf.len() != initial_leaf_f128
                || query.initial_path.len() != k_code
                || query.epoch_leaves.len() != num_fri_commits
                || query.epoch_paths.len() != num_fri_commits
            {
                return Err(VerifyError::InvalidProofShape);
            }
            let initial_hash = merkle::hash_leaf(&f128_slice_to_bytes(&query.initial_leaf));
            if !merkle::verify_merkle_proof_with_version(
                initial_codeword_root,
                &initial_hash,
                query.position,
                &query.initial_path,
                node_hash_version,
            ) {
                return Err(VerifyError::InitialMerkleFailed { query_index });
            }

            let post_row_batch_value =
                row_batch_fold_one_c1(&query.initial_leaf, &challenges[..log_batch_size]);
            let fri_challenge_start = log_batch_size;
            let mut cumulative_arity = first_arity;
            let mut expected = if arities.is_empty() {
                post_row_batch_value
            } else {
                if query.post_row_batch_leaf.len() != post_row_batch_leaf_f256
                    || query.post_row_batch_path.len() != k_code - first_arity
                {
                    return Err(VerifyError::InvalidProofShape);
                }
                let leaf_index = query.position >> first_arity;
                let leaf_hash = merkle::hash_leaf(&f256_slice_to_bytes(&query.post_row_batch_leaf));
                if !merkle::verify_merkle_proof_with_version(
                    &proof.post_row_batch_commit.root,
                    &leaf_hash,
                    leaf_index,
                    &query.post_row_batch_path,
                    node_hash_version,
                ) {
                    return Err(VerifyError::InitialMerkleFailed { query_index });
                }
                let offset = query.position & ((1usize << first_arity) - 1);
                if query.post_row_batch_leaf[offset] != post_row_batch_value {
                    return Err(VerifyError::FoldMismatch {
                        query_index,
                        epoch: 0,
                    });
                }
                fri_fold_coset_c1(
                    &query.post_row_batch_leaf,
                    &challenges[fri_challenge_start..fri_challenge_start + first_arity],
                    ntt,
                    k_code,
                    leaf_index,
                )
            };

            for epoch in 0..num_fri_commits {
                let leaf = &query.epoch_leaves[epoch];
                let next_arity = arities[epoch + 1];
                if leaf.len() != 1usize << next_arity {
                    return Err(VerifyError::InvalidProofShape);
                }
                let position_at_layer = query.position >> cumulative_arity;
                let leaf_index = position_at_layer >> next_arity;
                let offset = position_at_layer & ((1usize << next_arity) - 1);
                if query.epoch_paths[epoch].len() != k_code - cumulative_arity - next_arity {
                    return Err(VerifyError::InvalidProofShape);
                }
                let leaf_hash = merkle::hash_leaf(&f256_slice_to_bytes(leaf));
                if !merkle::verify_merkle_proof_with_version(
                    &proof.round_commitments[epoch].root,
                    &leaf_hash,
                    leaf_index,
                    &query.epoch_paths[epoch],
                    node_hash_version,
                ) {
                    return Err(VerifyError::RoundMerkleFailed { query_index, epoch });
                }
                if leaf[offset] != expected {
                    return Err(VerifyError::FoldMismatch { query_index, epoch });
                }
                let input_layer = k_code - cumulative_arity;
                expected = fri_fold_coset_c1(
                    leaf,
                    &challenges[fri_challenge_start + cumulative_arity
                        ..fri_challenge_start + cumulative_arity + next_arity],
                    ntt,
                    input_layer,
                    leaf_index,
                );
                cumulative_arity += next_arity;
            }

            if let Some((_, tail_cumulative_arity)) = tail_layout {
                debug_assert_eq!(cumulative_arity, tail_cumulative_arity);
                let tail_position = query.position >> cumulative_arity;
                if proof.plaintext_tail[tail_position] != expected {
                    return Err(VerifyError::FoldMismatch {
                        query_index,
                        epoch: num_fri_commits,
                    });
                }
            } else {
                let final_position = query.position >> cumulative_arity;
                if proof.final_codeword[final_position] != expected {
                    return Err(VerifyError::FoldMismatch {
                        query_index,
                        epoch: num_fri_commits,
                    });
                }
            }
            Ok(())
        })
        .collect::<Vec<_>>();
    for result in query_results {
        result?;
    }
    let queries_micros = queries_started.elapsed().as_micros();

    let tail_started = std::time::Instant::now();
    if let Some((tail_len, tail_cumulative_arity)) = tail_layout {
        let remaining = log_dim - tail_cumulative_arity;
        let coset_len = 1usize << remaining;
        debug_assert_eq!(tail_len >> remaining, 1usize << log_inv_rate);
        let fri_challenge_start = log_batch_size;
        let remaining_challenges =
            &challenges[fri_challenge_start + tail_cumulative_arity..fri_challenge_start + log_dim];
        let input_layer = k_code - tail_cumulative_arity;
        for final_index in 0..tail_len >> remaining {
            let folded = fri_fold_coset_c1(
                &proof.plaintext_tail[final_index * coset_len..(final_index + 1) * coset_len],
                remaining_challenges,
                ntt,
                input_layer,
                final_index,
            );
            if folded != proof.final_codeword[final_index] {
                return Err(VerifyError::FoldMismatch {
                    query_index: 0,
                    epoch: num_fri_commits,
                });
            }
        }
    }
    if timing {
        eprintln!(
            "[basefold-c1 verify] prefix_us={prefix_micros} queries_us={queries_micros} tail_us={} total_us={}",
            tail_started.elapsed().as_micros(),
            total_started.elapsed().as_micros(),
        );
    }

    Ok(challenges)
}

#[cfg(test)]
mod c1_tests {
    use super::*;
    use crate::challenger::FsLaneChallenger;
    use crate::pcs::{PcsParams, commit};

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

        fn f256(&mut self) -> F256 {
            F256::new(self.f128(), self.f128())
        }
    }

    #[test]
    fn c1_basefold_roundtrips_with_and_without_row_batching() {
        for log_batch_size in [0usize, 2] {
            let log_message_len = 8;
            let params = PcsParams {
                m: log_message_len + crate::pcs::LOG_PACKING,
                log_inv_rate: 2,
                log_batch_size,
                profile: Default::default(),
            };
            let mut rng = Rng(0xC1_BA5E_F01D + log_batch_size as u64);
            let message = (0..1usize << log_message_len)
                .map(|_| rng.f128())
                .collect::<Vec<_>>();
            let transparent = (0..message.len()).map(|_| rng.f256()).collect::<Vec<_>>();
            let target = message
                .iter()
                .zip(&transparent)
                .fold(F256::ZERO, |sum, (&left, &right)| {
                    sum + right.scale_base(left)
                });
            let (commitment, prover_data) = commit(&message, &params);
            let ntt = AdditiveNttF128::standard(params.k_code());
            let query_count = default_fri_queries(params.log_dim(), params.log_inv_rate);

            let mut prover = FsLaneChallenger::new_c1(b"c1-basefold-roundtrip");
            let proof = prove_c1(
                &message,
                transparent,
                target,
                &prover_data.codeword,
                &prover_data.merkle_tree,
                &ntt,
                params.log_inv_rate,
                params.log_batch_size,
                query_count,
                &mut prover,
            );
            let mut verifier = FsLaneChallenger::new_c1(b"c1-basefold-roundtrip");
            let challenges = verify_c1(
                target,
                &proof,
                &commitment.root,
                &ntt,
                params.log_msg_len(),
                params.log_inv_rate,
                params.log_batch_size,
                &mut verifier,
            )
            .unwrap_or_else(|error| {
                panic!("C1 BaseFold rejected at log_batch_size={log_batch_size}: {error:?}")
            });
            assert_eq!(challenges.len(), log_message_len);
            assert_eq!(prover.sample_f256(), verifier.sample_f256());

            let mut tampered = proof;
            tampered.round_messages[0].u_0 += F256::ONE;
            let mut verifier = FsLaneChallenger::new_c1(b"c1-basefold-roundtrip");
            assert!(
                verify_c1(
                    target,
                    &tampered,
                    &commitment.root,
                    &ntt,
                    params.log_msg_len(),
                    params.log_inv_rate,
                    params.log_batch_size,
                    &mut verifier,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn c1_fri_leaf_raw_and_canonical_encodings_match() {
        let mut rng = Rng(0xC1_1EA5);
        let values = (0..32).map(|_| rng.f256()).collect::<Vec<_>>();
        assert_eq!(f256_slice_as_bytes(&values), f256_slice_to_bytes(&values));
    }
}

#[cfg(test)]
mod security_configuration_tests {
    use super::*;

    #[test]
    fn every_published_basefold_domain_rate_is_finite_length_checked() {
        // Production recursive ladder: B25, B255/Link. Production
        // fixed helpers: checkpoint chunk core and receipt projection.
        let published = [
            (
                "recursive-m22",
                17usize,
                2usize,
                BASEFOLD_RATE_QUARTER_C1_QUERIES,
            ),
            ("recursive-m24", 19, 2, BASEFOLD_RATE_QUARTER_C1_QUERIES),
            ("checkpoint-chunk", 4, 4, 96),
            ("receipt-projection", 5, 4, 94),
        ];

        for (name, log_msg_cols, log_inv_rate, expected_queries) in published {
            let config = checked_fri_configuration(log_msg_cols, log_inv_rate)
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(config.query_count, expected_queries, "{name}");
            assert!(
                config.query_term_bits + 1e-9 >= BASEFOLD_UDR_TARGET_BITS as f64,
                "{name}: query term {}",
                config.query_term_bits
            );
            assert!(
                config.proximity_term_bits + 1e-9 >= BASEFOLD_UDR_TARGET_BITS as f64,
                "{name}: proximity term {}",
                config.proximity_term_bits
            );
        }
    }

    #[test]
    fn basefold_and_ligerito_share_the_corrected_finite_udr_algebra() {
        for log_inv_rate in 1..=5 {
            for log_msg_cols in 4..=19 {
                let Ok(config) = checked_fri_configuration(log_msg_cols, log_inv_rate) else {
                    continue;
                };
                let ligerito_gamma = crate::pcs::ligerito::udr_gamma(
                    log_inv_rate,
                    log_msg_cols,
                    crate::pcs::ligerito::UDR_PROXIMITY_LOSS,
                );
                let ligerito_query = crate::pcs::ligerito::udr_per_query_bits(
                    log_inv_rate,
                    log_msg_cols,
                    crate::pcs::ligerito::UDR_PROXIMITY_LOSS,
                );
                let ligerito_pg = 128.0
                    - crate::pcs::ligerito::paper_thm_1_4_log_a(
                        log_inv_rate,
                        log_msg_cols,
                        crate::pcs::ligerito::UDR_PROXIMITY_LOSS,
                    );
                assert!((config.proximity_radius - ligerito_gamma).abs() < 1e-12);
                assert!((config.per_query_bits - ligerito_query).abs() < 1e-12);
                assert!((config.proximity_term_bits - ligerito_pg).abs() < 1e-12);
            }
        }
    }

    #[test]
    fn c1_history_query_positions_have_exact_lane_geometry() {
        #[derive(Default)]
        struct CountingChallenger {
            requested_lanes: Vec<usize>,
        }

        impl Challenger for CountingChallenger {
            fn observe_f128(&mut self, _value: F128) {}

            fn sample_f128(&mut self) -> F128 {
                unreachable!("sample_query_positions must use one vector squeeze")
            }

            fn sample_f128_vec(&mut self, n: usize) -> Vec<F128> {
                self.requested_lanes.push(n);
                (0..n)
                    .map(|lane| F128 {
                        lo: lane as u64,
                        hi: !(lane as u64),
                    })
                    .collect()
            }
        }

        for k_code in [20usize, 21] {
            let mut challenger = CountingChallenger::default();
            let positions =
                sample_query_positions(&mut challenger, BASEFOLD_RATE_QUARTER_C1_QUERIES, k_code);
            assert_eq!(positions.len(), BASEFOLD_RATE_QUARTER_C1_QUERIES);
            assert_eq!(challenger.requested_lanes, [23]);
            assert!(
                positions
                    .iter()
                    .all(|&position| position < (1usize << k_code))
            );
        }
    }

    #[test]
    fn finite_length_gate_rejects_short_large_and_unpublished_configs() {
        assert_eq!(
            checked_fri_configuration(0, 1),
            Err(BaseFoldUdrConfigError::FiniteLengthTheoremPrecondition)
        );
        assert_eq!(
            checked_fri_configuration(30, 1),
            Err(BaseFoldUdrConfigError::ProximityTargetNotMet)
        );
        assert_eq!(
            checked_fri_configuration(19, 6),
            Err(BaseFoldUdrConfigError::UnsupportedInverseRate)
        );
    }
}
