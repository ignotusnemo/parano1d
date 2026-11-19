//! PCS commit phase: pack → RS encode (additive NTT) → Merkle root.
//!
//! Uses [`AdditiveNttF128`], the binius-style LCH NTT with neighbors-last
//! pairing. The commit produces a non-systematic RS codeword (treating the
//! packed witness as novel-basis coefficients, zero-padded to the larger
//! domain, then forward-NTT'd).
//!
//! ## Layout
//!
//! With parameters `(m, log_inv_rate)`:
//! - `log_msg_len = m − LOG_PACKING` (= log2 of packed witness length)
//! - `k_code      = log_msg_len + log_inv_rate` (= log2 of codeword length)
//!
//! The codeword is a flat sequence of `2^k_code` F_{2^128} elements. Each
//! Merkle leaf is **one** F_{2^128} element = 16 bytes.

use crate::field::F128;
use crate::merkle::{self, Hash};
use crate::ntt::AdditiveNttF128;
use crate::pcs::pack::LOG_PACKING;
use serde::{Deserialize, Serialize};

/// Authenticated PCS profile. The first three variants retain the exact
/// historical Ligerito-profile encoding and feed-forward BaseFold nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcsProfile {
    #[default]
    Fast,
    Slim,
    Secure,
    FixedCapacity,
}

impl PcsProfile {
    pub const fn node_hash_version(self) -> merkle::ProofNodeHashVersion {
        match self {
            Self::Fast | Self::Slim | Self::Secure => merkle::ProofNodeHashVersion::FeedForward,
            Self::FixedCapacity => merkle::ProofNodeHashVersion::FixedCapacity,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Slim => "slim",
            Self::Secure => "secure",
            Self::FixedCapacity => "fixed_capacity",
        }
    }

    pub const fn ligerito_profile(self) -> Option<crate::pcs::ligerito::LigeritoProfile> {
        use crate::pcs::ligerito::LigeritoProfile;
        match self {
            Self::Fast => Some(LigeritoProfile::Fast),
            Self::Slim => Some(LigeritoProfile::Slim),
            Self::Secure => Some(LigeritoProfile::Secure),
            Self::FixedCapacity => None,
        }
    }
}

impl From<crate::pcs::ligerito::LigeritoProfile> for PcsProfile {
    fn from(profile: crate::pcs::ligerito::LigeritoProfile) -> Self {
        use crate::pcs::ligerito::LigeritoProfile;
        match profile {
            LigeritoProfile::Fast => Self::Fast,
            LigeritoProfile::Slim => Self::Slim,
            LigeritoProfile::Secure => Self::Secure,
        }
    }
}

/// Log of the per-epoch FRI fold arity. `2^LOG_FRI_ARITY` codeword positions
/// fold together between Merkle commits. Bigger = fewer Merkle trees (cheaper
/// prover, fewer transcript roots) but bigger per-query leaves — and a
/// verifier that replays every query pays `2^LOG_FRI_ARITY / 2` permutations
/// per leaf per tree, which is what an in-circuit replay of this verifier
/// amortizes worst. Arity 4 (16-lane / 8-permutation leaves) balances the
/// replay cost against tree count; the previous arity 6 (64-lane / 33-perm
/// leaves at the time) made per-query leaf hashing the dominant term of the
/// whole recursive trace.
pub const LOG_FRI_ARITY: usize = 4;

/// Decompose `log_dim` FRI rounds into a sequence of epoch arities, each at
/// most [`LOG_FRI_ARITY`]. The last epoch may be smaller than [`LOG_FRI_ARITY`]
/// if `log_dim` doesn't divide evenly.
///
/// Examples (`LOG_FRI_ARITY = 4`):
/// - `log_dim = 14` → `[4, 4, 4, 2]`
/// - `log_dim = 8`  → `[4, 4]`
/// - `log_dim = 3`  → `[3]`
pub fn compute_fri_arities(log_dim: usize) -> Vec<usize> {
    let mut arities = Vec::new();
    let mut remaining = log_dim;
    while remaining > 0 {
        let a = remaining.min(LOG_FRI_ARITY);
        arities.push(a);
        remaining -= a;
    }
    arities
}

/// PCS configuration. Polynomial-basis subspace `{1, x, x², …}` for the NTT.
///
/// Interleaved RS: the packed witness is split into `2^log_batch_size`
/// independent sub-NTTs of size `2^log_dim` each. Each Merkle leaf holds one
/// codeword position across all `2^log_batch_size` lanes
/// (`2^log_batch_size · 16` bytes per leaf). Larger leaves reduce Merkle
/// overhead and scale better to large `m`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcsParams {
    pub m: usize,
    pub log_inv_rate: usize,
    /// Number of parallel sub-NTTs = `2^log_batch_size`. Default 5 (= 32 lanes).
    pub log_batch_size: usize,
    /// Security/hash profile. Historical Fast/Slim/Secure select the Ligerito
    /// parameters and retain legacy BaseFold nodes. FixedCapacity selects
    /// the versioned BaseFold node construction. Defaults to Fast.
    #[serde(default)]
    pub profile: PcsProfile,
}

impl PcsParams {
    pub const fn node_hash_version(&self) -> merkle::ProofNodeHashVersion {
        self.profile.node_hash_version()
    }
    /// Total log message length (= log2 packed witness length).
    pub fn log_msg_len(&self) -> usize {
        self.m - LOG_PACKING
    }
    /// Per-sub-NTT log dimension (= number of "position" coords).
    pub fn log_dim(&self) -> usize {
        self.log_msg_len() - self.log_batch_size
    }
    /// Codeword size (log) per sub-NTT.
    pub fn k_code(&self) -> usize {
        self.log_dim() + self.log_inv_rate
    }
    /// Number of Merkle leaves (= per-sub-NTT codeword length).
    pub fn n_positions(&self) -> usize {
        1usize << self.k_code()
    }
    /// `num_ntts` = `2^log_batch_size`.
    pub fn num_ntts(&self) -> usize {
        1usize << self.log_batch_size
    }
    /// Total codeword length in F_{2^128} elements
    /// (= `n_positions() * num_ntts()`).
    pub fn codeword_len_f128(&self) -> usize {
        self.n_positions() * self.num_ntts()
    }
    /// Per-epoch FRI arities (e.g. `[6, 6, 5]` for `log_dim = 17`). The first
    /// entry, `fri_arities()[0]`, sizes the **post-row-batch** Merkle leaf
    /// (built inside basefold::prove right after the row-batch sumcheck rounds).
    /// The **initial** Merkle commitment uses small leaves of just
    /// `2^log_batch_size = num_ntts` F_{2^128} values each — one codeword
    /// position's row-batch lanes per leaf.
    pub fn fri_arities(&self) -> Vec<usize> {
        compute_fri_arities(self.log_dim())
    }
    /// Log of the first-epoch FRI arity (= `fri_arities()[0]` if any, else 0).
    /// Drives the post-row-batch tree's leaf size, NOT the initial tree's.
    pub fn log_first_fri_arity(&self) -> usize {
        self.fri_arities().first().copied().unwrap_or(0)
    }
    /// `log_2` of the F_{2^128} count per **initial** Merkle leaf
    /// (= `log_batch_size`; just the row-batch lanes per position).
    pub fn log_leaf_f128_count(&self) -> usize {
        self.log_batch_size
    }
    /// Number of initial-tree Merkle leaves
    /// (= `codeword_len_f128() / 2^log_batch_size = 2^k_code`).
    pub fn n_leaves(&self) -> usize {
        self.codeword_len_f128() >> self.log_leaf_f128_count()
    }
    /// Merkle leaf size in bytes = `num_ntts() * 16`.
    pub fn leaf_size_bytes(&self) -> usize {
        16usize << self.log_leaf_f128_count()
    }

    fn validate(&self) {
        assert!(
            self.m >= LOG_PACKING + self.log_batch_size,
            "m={} too small (need m ≥ LOG_PACKING + log_batch_size = {})",
            self.m,
            LOG_PACKING + self.log_batch_size,
        );
        assert!(
            self.log_inv_rate >= 1,
            "log_inv_rate must be ≥ 1 for a non-trivial RS code",
        );
    }
}

/// Public commitment (Merkle root + params).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment {
    pub root: Hash,
    pub params: PcsParams,
}

/// Prover-side state retained after commit for use in the opening phase.
///
/// **The packed witness is NOT stored here.** The caller is responsible for
/// retaining its own copy of the packed witness across commit + open. This
/// avoids ~4 GB of duplication at large `m`, dropping peak commit memory by
/// a factor of ~1.5 (e.g. at m=35: 13 GB → 9 GB).
pub struct ProverData {
    pub codeword: Vec<F128>,
    pub merkle_tree: Vec<Hash>,
}

// Recycle the codeword buffer (the prover's largest single allocation —
// 128 MB at m = 29) through the scratch pool instead of unmapping it.
impl Drop for ProverData {
    fn drop(&mut self) {
        crate::scratch::give_f128(std::mem::take(&mut self.codeword));
    }
}

/// Commit to a witness in **F_{2^128}-packed** form (polynomial basis: bit
/// `r` of `z_packed[i]` = logical bit `i·128 + r`).
///
/// Uses **interleaved RS encoding**: `num_ntts = 2^log_batch_size` independent
/// sub-NTTs share the same domain and twiddles, processed via the SoA
/// interleaved transform. The codeword is stored position-major SoA
/// (`codeword[pos · num_ntts + lane]`); each Merkle leaf is one position =
/// `num_ntts` F_{2^128} = `num_ntts · 16` bytes.
///
/// **Takes the witness by reference**. The returned [`ProverData`] does NOT
/// retain a copy of the packed witness — the caller is responsible for
/// keeping its own copy across commit + open. This frees ~4 GB during the
/// NTT/Merkle phase at large `m`.
///
/// `z_packed.len()` must equal `2^(m - LOG_PACKING) = 2^(m - 7)`.
pub fn commit(z_packed: &[F128], params: &PcsParams) -> (Commitment, ProverData) {
    params.validate();
    assert_eq!(z_packed.len(), 1usize << params.log_msg_len());

    let num_ntts = params.num_ntts();
    let n_positions = params.n_positions();
    let codeword_len = n_positions * num_ntts;

    // ---- Codeword buffer (SoA): codeword[pos * num_ntts + lane].
    // The scratch contents are irrelevant: commit_into materializes the
    // zero-padded NTT prefix plus its first active layers directly from
    // `z_packed`, writing every codeword slot before it is read.
    let codeword = crate::scratch::take_f128(codeword_len);
    commit_into(z_packed, params, codeword)
}

/// Like [`commit`], but reuses a caller-provided codeword buffer instead of
/// allocating its own. The buffer must have length `codeword_len`; its
/// CONTENTS may be arbitrary (uninit/stale) — every slot is written here.
/// The zero-copy NTT prefix and first active layers are materialized directly
/// from `z_packed` in parallel. Buffers from [`prefault_codeword_during`] or
/// the scratch pool are already resident, so no write faults.
pub fn commit_into(
    z_packed: &[F128],
    params: &PcsParams,
    codeword: Vec<F128>,
) -> (Commitment, ProverData) {
    params.validate();
    assert_eq!(z_packed.len(), 1usize << params.log_msg_len());
    let codeword_len = params.n_positions() * params.num_ntts();
    assert_eq!(
        codeword.len(),
        codeword_len,
        "commit_into: prebuilt codeword buffer has wrong length"
    );

    finalize_commit(z_packed, codeword, params)
}

/// Fill `codeword` with `2^r` replicas of `msg` (`r = log2(codeword.len() /
/// msg.len())`) — the exact state after the first `r` forward-NTT layers on
/// the zero-padded coefficient vector `[msg, 0, …, 0]`. Pair with
/// `forward_transform_interleaved_from_layer(…, r)`. Every slot of `codeword`
/// is written (input contents may be stale/uninit).
pub(crate) fn replicate_message_fill(codeword: &mut [F128], msg: &[F128]) {
    use rayon::prelude::*;
    let msg_len = msg.len();
    debug_assert!(codeword.len().is_multiple_of(msg_len));
    const COPY_CHUNK: usize = 1 << 16;
    if msg_len >= COPY_CHUNK {
        // Both are powers of two, so chunks never straddle a replica boundary.
        codeword
            .par_chunks_mut(COPY_CHUNK)
            .enumerate()
            .for_each(|(i, dst)| {
                let src_off = (i * COPY_CHUNK) % msg_len;
                dst.copy_from_slice(&msg[src_off..src_off + dst.len()]);
            });
    } else {
        for rep in codeword.chunks_mut(msg_len) {
            rep.copy_from_slice(msg);
        }
    }
}

/// Materialize the exact state after the zero-copy prefix and the first two
/// active interleaved NTT layers.
///
/// A conventional commit first writes `2^start_layer` full replicas of
/// `msg`, then the NTT reads and writes that entire codeword again for layers
/// `start_layer` and `start_layer + 1`. The two layers form independent
/// four-row butterflies inside each replica. Evaluate those butterflies
/// directly from the shared message and write their final rows once. This is
/// algebraically identical to `replicate_message_fill` followed by the normal
/// fused two-layer transform, but removes one full codeword read and write.
///
/// Falls back to replica fill when fewer than two active layers remain. The
/// returned layer is the first layer the caller must still execute.
fn replicate_message_fill_fused_two_layers(
    codeword: &mut [F128],
    msg: &[F128],
    ntt: &AdditiveNttF128,
    num_ntts: usize,
    start_layer: usize,
) -> usize {
    use rayon::prelude::*;

    assert!(num_ntts.is_power_of_two() && num_ntts > 0);
    assert_eq!(msg.len() % num_ntts, 0);
    assert_eq!(codeword.len() % msg.len(), 0);
    let replicas = codeword.len() / msg.len();
    assert_eq!(replicas, 1usize << start_layer);
    debug_assert_eq!(codeword.len() / num_ntts, 1usize << ntt.log_domain_size());

    let msg_positions = msg.len() / num_ntts;
    if start_layer + 2 > ntt.log_domain_size() || msg_positions < 4 {
        replicate_message_fill(codeword, msg);
        return start_layer;
    }

    let quarter_positions = msg_positions / 4;
    let quarter_len = quarter_positions * num_ntts;
    debug_assert_eq!(4 * quarter_len, msg.len());
    let twiddles: Vec<(F128, F128, F128)> = (0..replicas)
        .map(|replica| {
            // At `start_layer`, replica `r` is global block r. Splitting it
            // for the next layer produces global blocks 2r and 2r+1.
            (
                ntt.twiddle(start_layer, replica),
                ntt.twiddle(start_layer + 1, 2 * replica),
                ntt.twiddle(start_layer + 1, 2 * replica + 1),
            )
        })
        .collect();

    // Tiny recursive commits do not amortize Rayon dispatch. Production's
    // B255 message is 256 MiB, far above this threshold.
    const PARALLEL_MSG_MIN: usize = 1 << 16;
    if msg.len() >= PARALLEL_MSG_MIN {
        codeword
            .par_chunks_mut(msg.len())
            .zip(twiddles.into_par_iter())
            .for_each(|(out, (t_outer, t_inner_top, t_inner_bottom))| {
                fill_fused_two_layer_replica(
                    out,
                    msg,
                    quarter_len,
                    num_ntts,
                    t_outer,
                    t_inner_top,
                    t_inner_bottom,
                    true,
                );
            });
    } else {
        for (out, (t_outer, t_inner_top, t_inner_bottom)) in
            codeword.chunks_mut(msg.len()).zip(twiddles)
        {
            fill_fused_two_layer_replica(
                out,
                msg,
                quarter_len,
                num_ntts,
                t_outer,
                t_inner_top,
                t_inner_bottom,
                false,
            );
        }
    }

    start_layer + 2
}

#[allow(clippy::too_many_arguments)]
fn fill_fused_two_layer_replica(
    out: &mut [F128],
    msg: &[F128],
    quarter_len: usize,
    num_ntts: usize,
    t_outer: F128,
    t_inner_top: F128,
    t_inner_bottom: F128,
    parallel: bool,
) {
    use rayon::prelude::*;

    debug_assert_eq!(out.len(), msg.len());
    debug_assert_eq!(out.len(), 4 * quarter_len);
    let (msg_top, msg_bottom) = msg.split_at(2 * quarter_len);
    let (msg_a, msg_b) = msg_top.split_at(quarter_len);
    let (msg_c, msg_d) = msg_bottom.split_at(quarter_len);
    let (out_top, out_bottom) = out.split_at_mut(2 * quarter_len);
    let (out_a, out_b) = out_top.split_at_mut(quarter_len);
    let (out_c, out_d) = out_bottom.split_at_mut(quarter_len);

    let apply_row = |row: usize,
                     dst_a: &mut [F128],
                     dst_b: &mut [F128],
                     dst_c: &mut [F128],
                     dst_d: &mut [F128]| {
        let offset = row * num_ntts;
        let src_a = &msg_a[offset..offset + num_ntts];
        let src_b = &msg_b[offset..offset + num_ntts];
        let src_c = &msg_c[offset..offset + num_ntts];
        let src_d = &msg_d[offset..offset + num_ntts];
        for lane in 0..num_ntts {
            // Layer start_layer: (a,c), (b,d).
            let a1 = src_a[lane] + src_c[lane] * t_outer;
            let c1 = src_c[lane] + a1;
            let b1 = src_b[lane] + src_d[lane] * t_outer;
            let d1 = src_d[lane] + b1;
            // Layer start_layer+1: (a,b), (c,d).
            let a2 = a1 + b1 * t_inner_top;
            let b2 = b1 + a2;
            let c2 = c1 + d1 * t_inner_bottom;
            let d2 = d1 + c2;
            dst_a[lane] = a2;
            dst_b[lane] = b2;
            dst_c[lane] = c2;
            dst_d[lane] = d2;
        }
    };

    if parallel {
        out_a
            .par_chunks_mut(num_ntts)
            .zip(out_b.par_chunks_mut(num_ntts))
            .zip(out_c.par_chunks_mut(num_ntts))
            .zip(out_d.par_chunks_mut(num_ntts))
            .enumerate()
            .for_each(|(row, (((dst_a, dst_b), dst_c), dst_d))| {
                apply_row(row, dst_a, dst_b, dst_c, dst_d);
            });
    } else {
        for (row, (((dst_a, dst_b), dst_c), dst_d)) in out_a
            .chunks_mut(num_ntts)
            .zip(out_b.chunks_mut(num_ntts))
            .zip(out_c.chunks_mut(num_ntts))
            .zip(out_d.chunks_mut(num_ntts))
            .enumerate()
        {
            apply_row(row, dst_a, dst_b, dst_c, dst_d);
        }
    }
}

/// Shared tail of [`commit`] / [`commit_into`]: interleaved forward additive
/// NTT (RS-encode every lane) then the initial Merkle tree over codeword rows.
fn finalize_commit(
    z_packed: &[F128],
    mut codeword: Vec<F128>,
    params: &PcsParams,
) -> (Commitment, ProverData) {
    let timing = std::env::var_os("NOIDH_COMMIT_TIMING").is_some();
    let t_ntt = std::time::Instant::now();
    // ---- Interleaved forward additive NTT: 2^log_batch_size independent
    // sub-NTTs with shared twiddles. Each sub-NTT operates on its lane of the
    // SoA buffer. Materialize the zero-copy prefix and the first two active
    // layers in one output pass, then run the remaining cache-blocked NTT.
    let ntt = AdditiveNttF128::standard(params.k_code());
    let start_layer = replicate_message_fill_fused_two_layers(
        &mut codeword,
        z_packed,
        &ntt,
        params.num_ntts(),
        params.log_inv_rate,
    );
    ntt.forward_transform_interleaved_from_layer(&mut codeword, params.num_ntts(), start_layer);
    if timing {
        eprintln!(
            "[commit-timing] ntt: {:.2} ms",
            t_ntt.elapsed().as_secs_f64() * 1e3
        );
    }
    let t_merkle = std::time::Instant::now();

    // ---- Merkle commitment: one leaf per codeword position = num_ntts F128.
    // Zero-copy: cast the codeword Vec<F128> directly to &[u8]. F128 is
    // repr(C, align(16)) with two u64s laid out little-endian — same bytes
    // as the explicit lo.to_le_bytes() + hi.to_le_bytes() serialization.
    let codeword_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            codeword.as_ptr() as *const u8,
            codeword.len() * core::mem::size_of::<F128>(),
        )
    };
    // Initial tree: one leaf per codeword position, each containing the
    // row-batch lanes (num_ntts F_{2^128} values = 2^log_batch_size). The
    // **post-row-batch** tree is built inside basefold::prove and provides
    // the multi-arity batching for the first FRI epoch.
    let merkle_tree = merkle::merkle_tree_with_version(
        codeword_bytes,
        params.n_leaves(),
        params.node_hash_version(),
    );
    let root = *merkle_tree.last().expect("merkle tree non-empty");
    if timing {
        eprintln!(
            "[commit-timing] merkle: {:.2} ms",
            t_merkle.elapsed().as_secs_f64() * 1e3
        );
    }

    (
        Commitment {
            root,
            params: params.clone(),
        },
        ProverData {
            codeword,
            merkle_tree,
        },
    )
}

/// Allocate + zero-fill (pre-fault) the codeword buffer that [`commit_into`]
/// will consume while `gen` runs on another worker from the caller's current
/// Rayon pool. Returns `(Some(buf), gen_result)`.
///
/// The codeword alloc is page-fault-bound (first-touch of a fresh 64–512 MB
/// buffer) and scales ~1.0×, so overlapping it with witness generation hides it
/// almost entirely (measured ~99% at m=29 — see `benches/ecore_offload_probe`).
///
/// Using `rayon::join` is part of the process CPU admission contract: every
/// cold concurrent proof shares the same fixed worker budget instead of each
/// spawning an unaccounted OS thread. With a one-worker pool the buffer is
/// allocated inline by [`commit`], preserving genuinely serial execution.
pub fn prefault_codeword_during<R: Send>(
    params: &PcsParams,
    generate: impl FnOnce() -> R + Send,
) -> (Option<Vec<F128>>, R) {
    if rayon::current_num_threads() <= 1 || std::env::var_os("NOIDH_NO_PREFAULT").is_some() {
        // Truly single-threaded (or explicitly disabled): no extra OS thread;
        // commit allocates inline. NOIDH_NO_PREFAULT lets benchmarks A/B the
        // offload and keeps fixed-thread-count sweeps honest.
        return (None, generate());
    }
    let codeword_len = params.n_positions() * params.num_ntts();
    // Warm path: a pooled buffer is already resident — there is nothing to
    // pre-fault, and commit_into writes every slot itself. Skip the thread.
    if let Some(buf) = crate::scratch::try_take_f128(codeword_len) {
        return (Some(buf), generate());
    }
    // Cold path: allocate + first-touch on one admitted Rayon worker while
    // another runs witness generation. `commit_into` rewrites every slot, so
    // only the page residency matters here.
    let (buf, result) = rayon::join(
        || {
            let mut buf: Vec<F128> = crate::alloc_uninit_f128_vec(codeword_len);
            unsafe {
                std::ptr::write_bytes(buf.as_mut_ptr(), 0u8, codeword_len);
            }
            buf
        },
        generate,
    );
    (Some(buf), result)
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_profile_encoding_and_new_profile_tag_are_canonical() {
        use super::{PcsParams, PcsProfile};
        use crate::pcs::ligerito::LigeritoProfile;
        for old in [
            LigeritoProfile::Fast,
            LigeritoProfile::Slim,
            LigeritoProfile::Secure,
        ] {
            let params = PcsParams {
                m: 30,
                log_inv_rate: 2,
                log_batch_size: 5,
                profile: old.into(),
            };
            let historical = bincode::serialize(&(30usize, 2usize, 5usize, old)).unwrap();
            assert_eq!(bincode::serialize(&params).unwrap(), historical);
            let decoded: PcsParams = bincode::deserialize(&historical).unwrap();
            assert_eq!(decoded.profile, params.profile);
            assert_eq!(
                decoded.node_hash_version(),
                crate::merkle::ProofNodeHashVersion::FeedForward
            );
        }
        let params = PcsParams {
            m: 30,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: PcsProfile::FixedCapacity,
        };
        let encoded = bincode::serialize(&params).unwrap();
        assert!(bincode::deserialize::<(usize, usize, usize, LigeritoProfile)>(&encoded).is_err());
        assert_eq!(
            bincode::deserialize::<PcsParams>(&encoded).unwrap().profile,
            PcsProfile::FixedCapacity
        );
    }

    use super::*;

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn bits(&mut self, n: usize) -> Vec<bool> {
            (0..n).map(|_| self.next_u64() & 1 == 1).collect()
        }
    }

    fn default_params(m: usize) -> PcsParams {
        PcsParams {
            m,
            log_inv_rate: 1,
            log_batch_size: 1,
            profile: Default::default(),
        }
    }

    /// The fused replica-prefix + parallel from-layer fast path must be
    /// byte-identical to the definitional encoding: zero-padded coefficients
    /// through the FULL scalar forward NTT. Covers rate 1/2 and 1/4 and both
    /// interleaving widths; root equality pins commitment identity too.
    #[test]
    fn commit_matches_full_ntt_oracle() {
        use crate::ntt::AdditiveNttF128;
        let mut rng = Rng::new(0xFEED);
        for (m, log_inv_rate, log_batch_size) in [
            (10, 1, 1),
            (12, 1, 2),
            (12, 2, 1),
            (14, 2, 3),
            // Crosses PARALLEL_MSG_MIN and log_d's cache-blocked threshold,
            // pinning the production iterator branches to the scalar oracle.
            (23, 1, 3),
        ] {
            let params = PcsParams {
                m,
                log_inv_rate,
                log_batch_size,
                profile: Default::default(),
            };
            let z = rng.bits(1 << m);
            let z_packed = super::super::pack::pack_witness(&z, m);

            let (commitment, pd) = commit(&z_packed, &params);

            // Oracle: explicit [z, 0, …, 0] coefficients, full NTT from layer 0.
            let mut oracle = vec![F128::ZERO; params.codeword_len_f128()];
            oracle[..z_packed.len()].copy_from_slice(&z_packed);
            let ntt = AdditiveNttF128::standard(params.k_code());
            ntt.forward_transform_interleaved_scalar(&mut oracle, params.num_ntts());

            assert_eq!(
                pd.codeword, oracle,
                "codeword mismatch at m={m} r={log_inv_rate}"
            );
            let oracle_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(oracle.as_ptr() as *const u8, oracle.len() * 16)
            };
            let oracle_root = *crate::merkle::merkle_tree(oracle_bytes, params.n_leaves())
                .last()
                .unwrap();
            assert_eq!(
                commitment.root, oracle_root,
                "root mismatch at m={m} r={log_inv_rate}"
            );
        }
    }

    #[test]
    fn commit_runs_and_produces_root() {
        let mut rng = Rng::new(42);
        for m in [8usize, 10, 12] {
            let z = rng.bits(1 << m);
            let z_packed = super::super::pack::pack_witness(&z, m);
            let params = default_params(m);
            let (commitment, prover_data) = commit(&z_packed, &params);
            assert_eq!(prover_data.codeword.len(), params.codeword_len_f128());
            assert_eq!(
                prover_data.merkle_tree.last().copied().unwrap(),
                commitment.root
            );
            assert_eq!(z_packed.len(), 1 << params.log_msg_len());
        }
    }

    #[test]
    fn commit_is_deterministic() {
        let mut rng = Rng::new(7);
        let m = 10;
        let z = rng.bits(1 << m);
        let z_packed = super::super::pack::pack_witness(&z, m);
        let params = default_params(m);
        let (c1, _) = commit(&z_packed, &params);
        let (c2, _) = commit(&z_packed, &params);
        assert_eq!(c1.root, c2.root);
    }

    #[test]
    fn commit_root_sensitive_to_witness() {
        let mut rng = Rng::new(99);
        let m = 10;
        let mut z = rng.bits(1 << m);
        let params = default_params(m);
        let (c1, _) = commit(&super::super::pack::pack_witness(&z, m), &params);
        z[7] ^= true;
        let (c2, _) = commit(&super::super::pack::pack_witness(&z, m), &params);
        assert_ne!(c1.root, c2.root);
    }

    #[test]
    fn rs_encoding_is_linear() {
        let mut rng = Rng::new(123);
        let m = 9;
        let params = default_params(m);
        let z1 = rng.bits(1 << m);
        let z2 = rng.bits(1 << m);
        let z_xor: Vec<bool> = z1.iter().zip(&z2).map(|(a, b)| a ^ b).collect();
        let pack = |z: &[bool]| super::super::pack::pack_witness(z, m);
        let (_, pd1) = commit(&pack(&z1), &params);
        let (_, pd2) = commit(&pack(&z2), &params);
        let (_, pd_x) = commit(&pack(&z_xor), &params);
        for (i, (&c1, &c2)) in pd1.codeword.iter().zip(&pd2.codeword).enumerate() {
            assert_eq!(c1 + c2, pd_x.codeword[i], "linearity fails at i={i}");
        }
    }

    #[test]
    fn codeword_doubles_message_length() {
        let mut rng = Rng::new(2);
        let m = 10;
        let params = default_params(m);
        let z = rng.bits(1 << m);
        let z_packed = super::super::pack::pack_witness(&z, m);
        let (_, pd) = commit(&z_packed, &params);
        assert_eq!(pd.codeword.len(), 2 * z_packed.len());
    }
}
