// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Parallel Poseidon2b PoW nonce search.
//!
//! PoW is computed over the fixed semantic header field schedule. Detached
//! nonce-independent witness data is prepared before this phase. The search
//! then owns the miner's shared all-core pool until it finds a nonce or is
//! cancelled. Latency-sensitive wallet proof and admission verification also
//! ask the search to drain at its next batch boundary; HistoryStep proving
//! starts only after the search has drained.
//!

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::le256_lt;
use noid_chain::consensus::pow::{pow_header_fields, PowNonceBatchHasher};

/// Result of a successful PoW search.
#[derive(Debug, Clone)]
pub struct PowSolution {
    pub nonce: u128,
    pub pow_hash: [u8; 32],
}

/// Search for a valid PoW nonce using the current Rayon pool.
/// Internal miner calls this inside the process-wide all-core PoW phase.
///
/// Detached witness fields are not part of the PoW hash; only semantic header
/// fields are absorbed under the `POWHDR__` domain.
///
/// Returns `Some(PowSolution)` when found, or `None` if cancelled via the
/// `cancel` channel (when a new P2P block arrives or a new template is ready).
pub fn search_pow_parallel(
    header_template: &BlockHeader,
    cancel: &std::sync::atomic::AtomicBool,
) -> Option<PowSolution> {
    use rayon::prelude::*;
    use std::sync::atomic::Ordering;

    // Start from a random nonce to avoid all miners/restarts colliding on nonce=0.
    // Uses a simple time-based seed — not cryptographic, just for nonce diversity.
    let random_start: u128 = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u128;
        // Mix with block height for additional diversity.
        (t ^ (header_template.height as u128).wrapping_mul(0x9E3779B97F4A7C15))
            & 0xFFFF_FFFF_FFFF_FFFF // 64-bit random start
    };

    // Partition the 128-bit nonce space into thread-sized chunks.
    // Each thread checks cancel once per nonce batch; this keeps cancellation
    // responsive without paying an atomic load for every permutation.
    const CHUNK_SIZE: u128 = 1_000_000;
    const DIGEST_BATCH: usize = 256;
    let target = header_template.difficulty_target;

    let mut start_nonce: u128 = random_start;

    // Hoist thread count — it never changes during a chunk.
    let num_threads = rayon::current_num_threads();
    let per_thread = CHUNK_SIZE.div_ceil(num_threads as u128);
    let fields = pow_header_fields(header_template);

    loop {
        if cancel.load(Ordering::Relaxed) || crate::cpu_budget::pow_preemption_requested() {
            return None;
        }

        // Search this chunk in parallel. Each thread reuses one canonical field
        // schedule and computes nonce digests in packed Poseidon2b batches.
        let chunk_end = start_nonce + CHUNK_SIZE;
        let solution: Option<PowSolution> =
            (0..num_threads).into_par_iter().find_map_any(|thread_id| {
                let thread_start = start_nonce + (thread_id as u128) * per_thread;
                let thread_end = (thread_start + per_thread).min(chunk_end);
                if thread_start >= thread_end {
                    return None;
                }
                let mut hasher = PowNonceBatchHasher::new(&fields);
                let mut digests = [[0u8; 32]; DIGEST_BATCH];
                let mut nonce = thread_start;

                while nonce < thread_end {
                    if cancel.load(Ordering::Relaxed)
                        || crate::cpu_budget::pow_preemption_requested()
                    {
                        return None;
                    }
                    let n = ((thread_end - nonce).min(DIGEST_BATCH as u128)) as usize;
                    hasher.hash_into(nonce, &mut digests[..n]);
                    for (i, hash) in digests[..n].iter().enumerate() {
                        if le256_lt(hash, &target) {
                            return Some(PowSolution {
                                nonce: nonce + i as u128,
                                pow_hash: *hash,
                            });
                        }
                    }
                    nonce += n as u128;
                }
                None
            });

        if solution.is_some() {
            return solution;
        }

        // Check cancellation before next chunk.
        if cancel.load(Ordering::Relaxed) || crate::cpu_budget::pow_preemption_requested() {
            return None;
        }

        // Advance to the next chunk.
        start_nonce = start_nonce.saturating_add(CHUNK_SIZE);
        if start_nonce == 0 {
            // Nonce space exhausted (extremely unlikely with 128-bit nonce).
            return None;
        }
    }
}
