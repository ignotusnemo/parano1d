//! Top-level R1CS verifier: walks the challenger in lockstep with the
//! prover, runs `zerocheck::verify` and `lincheck::verify`, derives the two
//! ZClaims, and verifies the PCS openings at those points against the
//! witness commitment.

use std::cell::Cell;
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};

use crate::challenger::Challenger;
use crate::field::{F128, F256};
use crate::lincheck::{self, QuirkyPoint};
use crate::pcs::{self, Commitment};
use crate::proof::{R1csClaim, R1csProof, R1csProofLigerito, ZClaim};
use crate::public_io::bind_post_commit_class;
use crate::r1cs::BlockR1cs;
use crate::zerocheck;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The commitment's PCS parameters do not match the instance shape.
    /// A hard error (not a debug assert): the snapshot decider feeds this
    /// path adversarial envelopes, and a mismatched `m` would otherwise
    /// size downstream structures from attacker-supplied bytes.
    ParamsMismatch,
    Zerocheck(zerocheck::VerifyError),
    Lincheck(lincheck::VerifyError),
    PcsAb(pcs::VerifyError),
    PcsC(pcs::VerifyError),
    /// A post-commit auxiliary protocol rejected before its terminal witness
    /// claims were appended to the shared PCS batch.
    Auxiliary,
}

/// Opaque capability handed only to a causally post-commit verifier callback.
/// It delegates the exact enclosing challenger and owns the claim sink that
/// the verifier automatically appends to the shared PCS batch.
pub struct FieldPostCommitVerifierContext<'a, Ch> {
    commitment: &'a Commitment,
    total_vars: usize,
    challenger: &'a mut Ch,
    claims: Vec<pcs::QuirkyDirectClaim>,
    c1_claims: Vec<pcs::C1QuirkyDirectClaim>,
}

impl<'a, Ch> FieldPostCommitVerifierContext<'a, Ch> {
    fn new(commitment: &'a Commitment, total_vars: usize, challenger: &'a mut Ch) -> Self {
        Self {
            commitment,
            total_vars,
            challenger,
            claims: Vec::new(),
            c1_claims: Vec::new(),
        }
    }

    fn finish(self) -> Vec<pcs::QuirkyDirectClaim> {
        assert!(
            self.c1_claims.is_empty(),
            "extension-field claims require a C1 enclosing proof"
        );
        self.claims
    }

    fn finish_c1(self) -> (Vec<pcs::QuirkyDirectClaim>, Vec<pcs::C1QuirkyDirectClaim>) {
        (self.claims, self.c1_claims)
    }

    pub fn commitment(&self) -> &'a Commitment {
        self.commitment
    }

    pub fn total_vars(&self) -> usize {
        self.total_vars
    }

    pub fn append_claim(&mut self, claim: pcs::QuirkyDirectClaim) {
        self.claims.push(claim);
    }

    pub fn append_claims(&mut self, claims: impl IntoIterator<Item = pcs::QuirkyDirectClaim>) {
        self.claims.extend(claims);
    }

    pub fn append_c1_claim(&mut self, claim: pcs::C1QuirkyDirectClaim) {
        self.c1_claims.push(claim);
    }

    pub fn append_c1_claims(&mut self, claims: impl IntoIterator<Item = pcs::C1QuirkyDirectClaim>) {
        self.c1_claims.extend(claims);
    }

    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }

    pub fn c1_claim_count(&self) -> usize {
        self.c1_claims.len()
    }
}

impl<Ch: Challenger> Challenger for FieldPostCommitVerifierContext<'_, Ch> {
    fn observe_label(&mut self, label: &[u8]) {
        self.challenger.observe_label(label);
    }

    fn observe_f128(&mut self, value: F128) {
        self.challenger.observe_f128(value);
    }

    fn observe_f128_slice(&mut self, values: &[F128]) {
        self.challenger.observe_f128_slice(values);
    }

    fn observe_f256(&mut self, value: F256) {
        self.challenger.observe_f256(value);
    }

    fn observe_f256_slice(&mut self, values: &[F256]) {
        self.challenger.observe_f256_slice(values);
    }

    fn observe_bytes(&mut self, bytes: &[u8]) {
        self.challenger.observe_bytes(bytes);
    }

    fn sample_f128(&mut self) -> F128 {
        self.challenger.sample_f128()
    }

    fn sample_f128_vec(&mut self, n: usize) -> Vec<F128> {
        self.challenger.sample_f128_vec(n)
    }

    fn sample_f256(&mut self) -> F256 {
        self.challenger.sample_f256()
    }

    fn sample_f256_vec(&mut self, n: usize) -> Vec<F256> {
        self.challenger.sample_f256_vec(n)
    }

    fn grind_pow(&mut self, bits: u32) -> u64 {
        self.challenger.grind_pow(bits)
    }

    fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        self.challenger.verify_pow(nonce, bits)
    }
}

/// Two bounded verifier lanes. Each proof remains strictly single-threaded,
/// while the history pipeline may verify B(N+1) and terminal Link(N) without
/// queueing both independent calls on one process-global worker.
const VERIFIER_LANES: usize = 2;

#[derive(Clone, Copy)]
struct ActiveVerifierLane {
    pool: usize,
    lane: usize,
}

thread_local! {
    // This is only a reentrancy marker on the two persistent pool workers;
    // pools themselves remain process-global and are never scope-thread local.
    static ACTIVE_VERIFIER_LANE: Cell<Option<ActiveVerifierLane>> = const { Cell::new(None) };
    // Production proof workers have a 64-MiB stack and belong to the node's
    // fixed CPU budget. They execute recursive verification in place instead
    // of activating one of the compatibility lanes below and exceeding that
    // process-wide budget. Library callers without such an executor retain
    // the two bounded large-stack lanes.
    static BUDGETED_LARGE_STACK_WORKER: Cell<bool> = const { Cell::new(false) };
}

/// Mark the current worker as belonging to an externally budgeted large-stack
/// proof pool. This is a low-level executor hook used by `noid_miner` worker
/// start/exit handlers; ordinary verifier callers must not enable it on a
/// default-size thread stack.
#[doc(hidden)]
pub fn set_budgeted_large_stack_worker(active: bool) {
    BUDGETED_LARGE_STACK_WORKER.with(|marker| marker.set(active));
}

struct ActiveVerifierLaneGuard(Option<ActiveVerifierLane>);

impl ActiveVerifierLaneGuard {
    fn enter(pool: usize, lane: usize) -> Self {
        Self(
            ACTIVE_VERIFIER_LANE
                .with(|active| active.replace(Some(ActiveVerifierLane { pool, lane }))),
        )
    }
}

impl Drop for ActiveVerifierLaneGuard {
    fn drop(&mut self) {
        ACTIVE_VERIFIER_LANE.with(|active| active.set(self.0));
    }
}

struct VerifierPools {
    lanes: [rayon::ThreadPool; VERIFIER_LANES],
    busy: Mutex<[bool; VERIFIER_LANES]>,
    available: Condvar,
    #[cfg(test)]
    wait_observer: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

struct VerifierLaneLease<'a> {
    pools: &'a VerifierPools,
    lane: usize,
}

impl Drop for VerifierLaneLease<'_> {
    fn drop(&mut self) {
        let mut busy = self
            .pools
            .busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        busy[self.lane] = false;
        self.pools.available.notify_one();
    }
}

impl VerifierPools {
    fn new() -> Self {
        let lanes = std::array::from_fn(|lane| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                // The deep recursive Ligerito verifier needs more than the
                // default ~2 MiB worker stack. Stack pages remain demand-paged.
                .stack_size(64 * 1024 * 1024)
                .thread_name(move |_| format!("history-verify-{lane}"))
                .build()
                .expect("build single-thread verifier lane")
        });
        Self {
            lanes,
            busy: Mutex::new([false; VERIFIER_LANES]),
            available: Condvar::new(),
            #[cfg(test)]
            wait_observer: Mutex::new(None),
        }
    }

    fn acquire(&self) -> VerifierLaneLease<'_> {
        let mut busy = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(lane) = busy.iter().position(|occupied| !*occupied) {
                busy[lane] = true;
                return VerifierLaneLease { pools: self, lane };
            }
            #[cfg(test)]
            if let Some(observer) = self
                .wait_observer
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
            {
                // An unbounded test channel cannot block while `busy` is held.
                let _ = observer.send(());
            }
            busy = self
                .available
                .wait(busy)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn install<OP, R>(&self, op: OP) -> R
    where
        OP: FnOnce() -> R + Send,
        R: Send,
    {
        let pool_id = self as *const Self as usize;
        let active = ACTIVE_VERIFIER_LANE.with(std::cell::Cell::get);
        if let Some(active) = active.filter(|active| active.pool == pool_id) {
            // A post-commit callback may recursively invoke a verifier. Reuse
            // its current one-thread lane exactly as the former single pool did.
            return self.lanes[active.lane].install(op);
        }

        let lease = self.acquire();
        let lane = lease.lane;
        self.lanes[lane].install(move || {
            // The lane worker, rather than a possibly-helping caller from a
            // different Rayon pool, must own the lease.  A cross-pool
            // `ThreadPool::install` lets its caller execute other local jobs
            // while it waits; retaining leases on that caller's nested stack
            // can otherwise consume both lanes before a third job blocks it,
            // preventing either completed lane from being released.
            let _lease = lease;
            let _active = ActiveVerifierLaneGuard::enter(pool_id, lane);
            op()
        })
    }
}

fn verifier_pools() -> &'static VerifierPools {
    static POOLS: OnceLock<VerifierPools> = OnceLock::new();
    POOLS.get_or_init(VerifierPools::new)
}

fn install_verifier<OP, R>(op: OP) -> R
where
    OP: FnOnce() -> R + Send,
    R: Send,
{
    if BUDGETED_LARGE_STACK_WORKER.with(Cell::get) {
        return op();
    }
    verifier_pools().install(op)
}

pub fn verify<Ch: Challenger>(
    r1cs: &BlockR1cs,
    commitment: &Commitment,
    proof: &R1csProof,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    // ---- Replay zerocheck + lincheck → the two base claims.
    let (ab, c) = verify_core(
        r1cs,
        &proof.zerocheck,
        &proof.lincheck,
        commitment,
        lincheck_circuit,
        challenger,
    )?;

    // ---- Verify the batched PCS opening covering both z-claims.
    verify_claims(
        commitment,
        &[ab.clone(), c.clone()],
        &proof.pcs_open,
        challenger,
    )
    .map_err(VerifyError::PcsAb)?;

    Ok(R1csClaim { ab, c })
}

/// Ligerito-backend mirror of [`verify`]. Same FS protocol replay; only the
/// final PCS verification step differs.
pub fn verify_ligerito<Ch: Challenger>(
    r1cs: &BlockR1cs,
    commitment: &Commitment,
    proof: &R1csProofLigerito,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    pcs_params: &crate::pcs::PcsParams,
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    let (ab, c) = verify_core(
        r1cs,
        &proof.zerocheck,
        &proof.lincheck,
        commitment,
        lincheck_circuit,
        challenger,
    )?;
    verify_claims_ligerito(
        commitment,
        &[ab.clone(), c.clone()],
        &proof.pcs_open,
        pcs_params,
        challenger,
    )
    .map_err(VerifyError::PcsAb)?;
    Ok(R1csClaim { ab, c })
}

/// Ligerito-backend mirror of [`verify_claims`].
pub fn verify_claims_ligerito<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProofLigerito,
    pcs_params: &crate::pcs::PcsParams,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    // Verification is single-threaded; run the body on one bounded verifier lane.
    install_verifier(move || {
        verify_claims_ligerito_inner(commitment, claims, pcs_open, pcs_params, challenger)
    })
}

fn verify_claims_ligerito_inner<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProofLigerito,
    pcs_params: &crate::pcs::PcsParams,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    let z_skips: Vec<F128> = claims.iter().map(|c| c.point.z_skip).collect();
    let values: Vec<F128> = claims.iter().map(|c| c.value).collect();
    let x_fulls: Vec<Vec<F128>> = claims
        .iter()
        .map(|c| {
            let mut v = c.point.x_inner_rest.clone();
            v.extend_from_slice(&c.point.x_outer);
            v
        })
        .collect();
    let x_refs: Vec<&[F128]> = x_fulls.iter().map(|v| v.as_slice()).collect();
    let log_n = pcs_params.m - pcs::LOG_PACKING;
    let lig_v_config = crate::pcs::ligerito::verifier_config_for(
        log_n,
        pcs_params.log_batch_size,
        pcs_params
            .profile
            .ligerito_profile()
            .ok_or(pcs::VerifyError::ProfileMismatch)?,
    )
    .expect("Ligerito default verifier config");
    pcs::verify_opening_batch_ligerito_mixed(
        commitment,
        &values,
        &z_skips,
        &x_refs,
        &[],
        pcs_open,
        &lig_v_config,
        challenger,
    )
}

/// Replay bind → zerocheck → lincheck and reconstruct the two base z-claims
/// (`ab`, `c`), stopping before the PCS open. Mirror of
/// `noid_ivc_prover::prover::prove_fast_core`; relation wrappers reuse this then call
/// [`verify_claims`] over `[ab, c, …]`.
pub fn verify_core<Ch: Challenger>(
    r1cs: &BlockR1cs,
    zerocheck_proof: &zerocheck::ZerocheckProof,
    lincheck_proof: &lincheck::LincheckProof,
    commitment: &Commitment,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    challenger: &mut Ch,
) -> Result<(ZClaim, ZClaim), VerifyError> {
    // Verification is single-threaded; run the body on one bounded verifier lane.
    install_verifier(move || {
        verify_core_inner(
            r1cs,
            zerocheck_proof,
            lincheck_proof,
            commitment,
            lincheck_circuit,
            challenger,
        )
    })
}

fn verify_core_inner<Ch: Challenger>(
    r1cs: &BlockR1cs,
    zerocheck_proof: &zerocheck::ZerocheckProof,
    lincheck_proof: &lincheck::LincheckProof,
    commitment: &Commitment,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    challenger: &mut Ch,
) -> Result<(ZClaim, ZClaim), VerifyError> {
    // Boolean-witness path: the packed commitment covers exactly the 2^m
    // witness bits. Same hard shape gate as the field path.
    if commitment.params.m != r1cs.m
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }

    let trace = std::env::var("VERIFY_TRACE").is_ok();
    let fmt = |s: f64| -> String {
        let ms = s * 1000.0;
        if ms < 1.0 {
            format!("{:>8.2} µs", s * 1e6)
        } else {
            format!("{:>8.2} ms", ms)
        }
    };

    // ---- Bind FS transcript to the statement (mirrors prover::prove).
    let t = std::time::Instant::now();
    crate::proof::bind_statement(challenger, r1cs, commitment);
    if trace {
        eprintln!(
            "      [vco] bind_statement: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // ---- Zerocheck.
    let t = std::time::Instant::now();
    let zc_claim =
        zerocheck::verify(r1cs.m, zerocheck_proof, challenger).map_err(VerifyError::Zerocheck)?;
    if trace {
        eprintln!(
            "      [vco] zerocheck::verify: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // ---- Build lincheck's shared quirky point from the zerocheck output.
    let inner_rest_len = r1cs.k_log - r1cs.k_skip;
    let x_ab = QuirkyPoint {
        z_skip: zc_claim.z,
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };

    // ---- Lincheck. v_a, v_b come from the zerocheck's final â, b̂ evals.
    let t = std::time::Instant::now();
    let lc_claim = lincheck::verify(
        r1cs.m,
        r1cs.k_log,
        r1cs.k_skip,
        lincheck_circuit,
        &x_ab,
        zc_claim.a_eval,
        zc_claim.b_eval,
        lincheck_proof,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;
    if trace {
        eprintln!(
            "      [vco] lincheck::verify: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // ---- Build the two z-claims (must match what `prove` returned).
    let ab = ZClaim {
        point: QuirkyPoint {
            z_skip: lc_claim.r_inner_skip,
            x_inner_rest: lc_claim.r_inner_rest.clone(),
            x_outer: x_ab.x_outer.clone(),
        },
        value: lc_claim.w,
    };
    // c-claim is already a z-claim since `C = I` ⇒ ĉ = ẑ.
    let c = ZClaim {
        point: QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zc_claim.c_eval,
    };

    Ok((ab, c))
}

/// Verify a batched PCS opening over an arbitrary list of `ẑ`-claims — the
/// mirror of `noid_ivc_prover::prover::open_claims`. Relation wrappers (e.g. the hash
/// chain) reuse this with their own appended claims. Must run at the same
/// transcript position as the prover's open.
pub fn verify_claims<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProof,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    // Verification is single-threaded; run the body on one bounded verifier lane.
    install_verifier(move || verify_claims_inner(commitment, claims, pcs_open, challenger))
}

fn verify_claims_inner<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProof,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    let z_skips: Vec<F128> = claims.iter().map(|c| c.point.z_skip).collect();
    let values: Vec<F128> = claims.iter().map(|c| c.value).collect();
    let x_fulls: Vec<Vec<F128>> = claims
        .iter()
        .map(|c| {
            let mut v = c.point.x_inner_rest.clone();
            v.extend_from_slice(&c.point.x_outer);
            v
        })
        .collect();
    let x_refs: Vec<&[F128]> = x_fulls.iter().map(|v| v.as_slice()).collect();
    pcs::verify_opening_batch(commitment, &values, &z_skips, &x_refs, pcs_open, challenger)
}

/// Verify a **FieldR1cs** proof: field zerocheck → shared lincheck
/// (coefficient-carrying circuit) → batched quirky-direct PCS opening.
/// Structural mirror of [`verify`]; same single-thread-per-call lane policy.
pub fn verify_field<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    install_verifier(move || {
        verify_field_inner(r1cs, commitment, proof, None, challenger, |_, _| {
            Ok(Vec::new())
        })
    })
}

/// Verify the closed native C1 History chain. No profile flag is accepted;
/// the proof type, statement domain, and every algebraic transcript move are
/// intrinsically wide.
pub fn verify_field_c1<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::C1FieldR1csProof,
    challenger: &mut Ch,
) -> Result<crate::proof::C1R1csClaim, VerifyError> {
    install_verifier(move || verify_field_c1_inner(r1cs, commitment, proof, challenger))
}

fn verify_field_c1_inner<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::C1FieldR1csProof,
    challenger: &mut Ch,
) -> Result<crate::proof::C1R1csClaim, VerifyError> {
    if commitment.params.m != r1cs.m + pcs::LOG_PACKING
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }
    crate::proof::bind_statement_field_c1(challenger, r1cs, commitment);

    let zerocheck_claim = zerocheck::field_c1::verify(r1cs.m, &proof.zerocheck, challenger)
        .map_err(VerifyError::Zerocheck)?;
    let inner_rest_len = r1cs.k_log - r1cs.k_skip;
    let lincheck_point = lincheck::c1::C1QuirkyPoint {
        z_skip: zerocheck_claim.z,
        x_inner_rest: zerocheck_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zerocheck_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    let row_circuit = crate::field_r1cs::FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
    let lincheck_claim = lincheck::c1::verify(
        r1cs.m,
        r1cs.k_log,
        r1cs.k_skip,
        &row_circuit,
        &lincheck_point,
        zerocheck_claim.a_eval,
        zerocheck_claim.b_eval,
        &proof.lincheck,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;

    let ab = crate::proof::C1ZClaim {
        point: lincheck::c1::C1QuirkyPoint {
            z_skip: lincheck_claim.r_inner_skip,
            x_inner_rest: lincheck_claim.r_inner_rest.clone(),
            x_outer: lincheck_point.x_outer.clone(),
        },
        value: lincheck_claim.w,
    };
    let c = crate::proof::C1ZClaim {
        point: lincheck::c1::C1QuirkyPoint {
            z_skip: zerocheck_claim.z,
            x_inner_rest: zerocheck_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zerocheck_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zerocheck_claim.c_eval,
    };
    let x_rest = |claim: &crate::proof::C1ZClaim| {
        let mut rest = claim.point.x_inner_rest.clone();
        rest.extend_from_slice(&claim.point.x_outer);
        rest
    };
    let ab_rest = x_rest(&ab);
    let c_rest = x_rest(&c);
    let refs = [
        pcs::C1QuirkyDirectClaimRef {
            z_skip: ab.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: &ab_rest,
            value: ab.value,
        },
        pcs::C1QuirkyDirectClaimRef {
            z_skip: c.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: &c_rest,
            value: c.value,
        },
    ];
    pcs::verify_opening_batch_quirky_direct_c1(commitment, &refs, &proof.pcs_open, challenger)
        .map_err(VerifyError::PcsAb)?;

    Ok(crate::proof::C1R1csClaim { ab, c })
}

/// [`verify_field`] with a public-IO envelope: mirrors
/// `prove_field_with_public_io` — absorbs the spec + envelope lanes right
/// after the statement binding, samples the binding point, and checks the
/// appended IO claims in the batched PCS opening (see
/// [`crate::public_io`]). The spec is a verification-key constant; the
/// envelope lanes are the proof's public values.
pub fn verify_field_with_public_io<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    install_verifier(move || {
        verify_field_inner(
            r1cs,
            commitment,
            proof,
            Some((spec, io)),
            challenger,
            |_, _| Ok(Vec::new()),
        )
    })
}

/// [`verify_field_with_public_io`] plus a post-commit auxiliary verifier.
///
/// This mirrors
/// `noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit`:
/// the callback runs after the statement/commitment/public-IO binding and
/// before the outer zerocheck. It must replay the auxiliary proof in the same
/// challenger and return its terminal claims on this exact commitment.
pub fn verify_field_with_public_io_and_post_commit<Ch, Aux, PostCommit>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<R1csClaim, VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit: FnOnce(&Aux, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError> + Send,
{
    install_verifier(move || {
        verify_field_inner(
            r1cs,
            commitment,
            proof,
            Some((spec, io)),
            challenger,
            |_, challenger| post_commit(auxiliary, challenger),
        )
    })
}

/// Typestate verifier twin of
/// `noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context`.
/// The class digest is absorbed after public IO and before the callback.  The
/// callback writes terminal claims into the opaque context; this wrapper
/// appends them to the shared PCS batch automatically.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_with_public_io_and_post_commit_context<Ch, Aux, PostCommit>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    post_commit_class_digest: &[u8; 32],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<R1csClaim, VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit:
        FnOnce(&Aux, &mut FieldPostCommitVerifierContext<'_, Ch>) -> Result<(), VerifyError> + Send,
{
    install_verifier(move || {
        verify_field_inner(
            r1cs,
            commitment,
            proof,
            Some((spec, io)),
            challenger,
            |commitment, challenger| {
                bind_post_commit_class(challenger, post_commit_class_digest);
                let mut context =
                    FieldPostCommitVerifierContext::new(commitment, r1cs.m, challenger);
                post_commit(auxiliary, &mut context)?;
                Ok(context.finish())
            },
        )
    })
}

/// Matrix-free verification for the self-verification chain: transcript-
/// identical to [`verify_field_with_public_io`], but the lincheck final
/// consistency is DEFERRED — the function returns the bilinear claim the
/// instance matrices must satisfy (see [`crate::matrix_claim`]) instead of
/// checking it against them. The statement enters through its digest and
/// shape parameters only, so a trace twin of this function can verify
/// proofs of its own class. The caller MUST fold + eventually discharge
/// the returned claim; acceptance here alone binds the proof to SOME
/// matrices, not to the instance's.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_deferred_matrix<Ch: Challenger>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    challenger: &mut Ch,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError> {
    install_verifier(move || {
        verify_field_deferred_matrix_inner(
            shape,
            statement_digest,
            commitment,
            proof,
            spec,
            io,
            challenger,
            |_, _| Ok(Vec::new()),
        )
    })
}

/// Matrix-free [`verify_field_deferred_matrix`] with a post-commit auxiliary
/// verifier. The callback ordering and terminal-claim semantics are identical
/// to [`verify_field_with_public_io_and_post_commit`].
#[allow(clippy::too_many_arguments)]
pub fn verify_field_deferred_matrix_with_post_commit<Ch, Aux, PostCommit>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit: FnOnce(&Aux, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError> + Send,
{
    install_verifier(move || {
        verify_field_deferred_matrix_inner(
            shape,
            statement_digest,
            commitment,
            proof,
            spec,
            io,
            challenger,
            |_, challenger| post_commit(auxiliary, challenger),
        )
    })
}

/// Matrix-free typestate twin of
/// [`verify_field_with_public_io_and_post_commit_context`].  It binds the same
/// explicit auxiliary class and uses the same append-only claim context before
/// returning the deferred matrix claim.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_deferred_matrix_with_post_commit_context<Ch, Aux, PostCommit>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    post_commit_class_digest: &[u8; 32],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit:
        FnOnce(&Aux, &mut FieldPostCommitVerifierContext<'_, Ch>) -> Result<(), VerifyError> + Send,
{
    install_verifier(move || {
        verify_field_deferred_matrix_inner(
            shape,
            statement_digest,
            commitment,
            proof,
            spec,
            io,
            challenger,
            |commitment, challenger| {
                bind_post_commit_class(challenger, post_commit_class_digest);
                let mut context =
                    FieldPostCommitVerifierContext::new(commitment, shape.m, challenger);
                post_commit(auxiliary, &mut context)?;
                Ok(context.finish())
            },
        )
    })
}

/// C1 production verifier with public IO, typed post-commit sidecars and a
/// deferred matrix terminal. The sidecar claim coordinates are F128 protocol
/// outputs and are embedded canonically into the extension-field PCS batch.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_c1_deferred_matrix_with_post_commit_context<Ch, Aux, PostCommit>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::C1FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    post_commit_class_digest: &[u8; 32],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<
    (
        crate::proof::C1R1csClaim,
        crate::matrix_claim::c1::C1FreshLincheckClaim,
    ),
    VerifyError,
>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit:
        FnOnce(&Aux, &mut FieldPostCommitVerifierContext<'_, Ch>) -> Result<(), VerifyError> + Send,
{
    install_verifier(move || {
        verify_field_c1_deferred_matrix_inner(
            shape,
            statement_digest,
            commitment,
            proof,
            spec,
            io,
            challenger,
            |commitment, challenger| {
                bind_post_commit_class(challenger, post_commit_class_digest);
                let mut context =
                    FieldPostCommitVerifierContext::new(commitment, shape.m, challenger);
                post_commit(auxiliary, &mut context)?;
                Ok(context.finish_c1())
            },
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_field_c1_deferred_matrix_inner<Ch: Challenger>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::C1FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    challenger: &mut Ch,
    post_commit: impl FnOnce(
        &Commitment,
        &mut Ch,
    ) -> Result<
        (Vec<pcs::QuirkyDirectClaim>, Vec<pcs::C1QuirkyDirectClaim>),
        VerifyError,
    >,
) -> Result<
    (
        crate::proof::C1R1csClaim,
        crate::matrix_claim::c1::C1FreshLincheckClaim,
    ),
    VerifyError,
> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    if commitment.params.m != shape.m + pcs::LOG_PACKING
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }

    crate::proof::bind_statement_field_parts_c1(challenger, statement_digest, commitment);
    let io_claims = crate::public_io::bind_public_io_c1(challenger, spec, io, shape.m);
    let prefix_micros = total_started.elapsed().as_micros();
    let auxiliary_started = std::time::Instant::now();
    let (auxiliary_claims, auxiliary_c1_claims) = post_commit(commitment, challenger)?;
    let auxiliary_micros = auxiliary_started.elapsed().as_micros();

    let zerocheck_started = std::time::Instant::now();
    let zerocheck_claim = zerocheck::field_c1::verify(shape.m, &proof.zerocheck, challenger)
        .map_err(VerifyError::Zerocheck)?;
    let zerocheck_micros = zerocheck_started.elapsed().as_micros();
    let inner_rest_len = shape.k_log - shape.k_skip;
    let lincheck_point = lincheck::c1::C1QuirkyPoint {
        z_skip: zerocheck_claim.z,
        x_inner_rest: zerocheck_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zerocheck_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    let lincheck_started = std::time::Instant::now();
    let (lincheck_claim, fresh) = lincheck::c1::verify_deferred(
        shape.m,
        shape.k_log,
        shape.k_skip,
        shape.const_pin,
        &lincheck_point,
        zerocheck_claim.a_eval,
        zerocheck_claim.b_eval,
        &proof.lincheck,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;
    let lincheck_micros = lincheck_started.elapsed().as_micros();

    let claims_started = std::time::Instant::now();
    let ab = crate::proof::C1ZClaim {
        point: lincheck::c1::C1QuirkyPoint {
            z_skip: lincheck_claim.r_inner_skip,
            x_inner_rest: lincheck_claim.r_inner_rest.clone(),
            x_outer: lincheck_point.x_outer.clone(),
        },
        value: lincheck_claim.w,
    };
    let c = crate::proof::C1ZClaim {
        point: lincheck::c1::C1QuirkyPoint {
            z_skip: zerocheck_claim.z,
            x_inner_rest: zerocheck_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zerocheck_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zerocheck_claim.c_eval,
    };
    let rest = |claim: &crate::proof::C1ZClaim| {
        let mut coordinates = claim.point.x_inner_rest.clone();
        coordinates.extend_from_slice(&claim.point.x_outer);
        coordinates
    };
    let mut claims = vec![
        pcs::C1QuirkyDirectClaim {
            z_skip: ab.point.z_skip,
            k_skip: shape.k_skip,
            x_rest: rest(&ab),
            value: ab.value,
        },
        pcs::C1QuirkyDirectClaim {
            z_skip: c.point.z_skip,
            k_skip: shape.k_skip,
            x_rest: rest(&c),
            value: c.value,
        },
    ];
    claims.extend(io_claims);
    claims.extend(
        auxiliary_claims
            .into_iter()
            .map(|claim| pcs::C1QuirkyDirectClaim {
                z_skip: F256::from_base(claim.z_skip),
                k_skip: claim.k_skip,
                x_rest: claim.x_rest.into_iter().map(F256::from_base).collect(),
                value: F256::from_base(claim.value),
            }),
    );
    claims.extend(auxiliary_c1_claims);
    let refs = claims
        .iter()
        .map(|claim| pcs::C1QuirkyDirectClaimRef {
            z_skip: claim.z_skip,
            k_skip: claim.k_skip,
            x_rest: &claim.x_rest,
            value: claim.value,
        })
        .collect::<Vec<_>>();
    let claims_micros = claims_started.elapsed().as_micros();
    let pcs_started = std::time::Instant::now();
    pcs::verify_opening_batch_quirky_direct_c1(commitment, &refs, &proof.pcs_open, challenger)
        .map_err(VerifyError::PcsAb)?;
    let pcs_micros = pcs_started.elapsed().as_micros();

    if timing {
        eprintln!(
            "[field-c1 verify] prefix_us={prefix_micros} auxiliary_us={auxiliary_micros} zerocheck_us={zerocheck_micros} lincheck_us={lincheck_micros} claims_us={claims_micros} pcs_us={pcs_micros} total_us={}",
            total_started.elapsed().as_micros(),
        );
    }

    Ok((crate::proof::C1R1csClaim { ab, c }, fresh))
}

#[allow(clippy::too_many_arguments)]
fn verify_field_deferred_matrix_inner<Ch: Challenger>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    challenger: &mut Ch,
    post_commit: impl FnOnce(&Commitment, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError>,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError> {
    if commitment.params.m != shape.m + pcs::LOG_PACKING
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }

    crate::proof::bind_statement_field_parts(challenger, statement_digest, commitment);
    let io_claims = crate::public_io::bind_public_io(challenger, spec, io, shape.m);
    let auxiliary_claims = post_commit(commitment, challenger)?;

    let zc_claim = zerocheck::field::verify(shape.m, &proof.zerocheck, challenger)
        .map_err(VerifyError::Zerocheck)?;

    let inner_rest_len = shape.k_log - shape.k_skip;
    let x_ab = QuirkyPoint {
        z_skip: zc_claim.z,
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    let (lc_claim, fresh) = lincheck::verify_deferred(
        shape.m,
        shape.k_log,
        shape.k_skip,
        shape.const_pin,
        &x_ab,
        zc_claim.a_eval,
        zc_claim.b_eval,
        &proof.lincheck,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;

    let ab = ZClaim {
        point: QuirkyPoint {
            z_skip: lc_claim.r_inner_skip,
            x_inner_rest: lc_claim.r_inner_rest.clone(),
            x_outer: x_ab.x_outer.clone(),
        },
        value: lc_claim.w,
    };
    let c = ZClaim {
        point: QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zc_claim.c_eval,
    };

    let x_rest_of = |zc: &ZClaim| -> Vec<F128> {
        let mut v = zc.point.x_inner_rest.clone();
        v.extend_from_slice(&zc.point.x_outer);
        v
    };
    let ab_rest = x_rest_of(&ab);
    let c_rest = x_rest_of(&c);
    let mut refs = vec![
        pcs::QuirkyDirectClaimRef {
            z_skip: ab.point.z_skip,
            k_skip: shape.k_skip,
            x_rest: &ab_rest,
            value: ab.value,
        },
        pcs::QuirkyDirectClaimRef {
            z_skip: c.point.z_skip,
            k_skip: shape.k_skip,
            x_rest: &c_rest,
            value: c.value,
        },
    ];
    refs.extend(io_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    refs.extend(auxiliary_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    pcs::verify_opening_batch_quirky_direct(commitment, &refs, &proof.pcs_open, challenger)
        .map_err(VerifyError::PcsAb)?;

    Ok((R1csClaim { ab, c }, fresh))
}

fn verify_field_inner<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    public_io: Option<(&crate::public_io::PublicIoSpec, &[crate::field::F128])>,
    challenger: &mut Ch,
    post_commit: impl FnOnce(&Commitment, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError>,
) -> Result<R1csClaim, VerifyError> {
    // The commitment must be sized for THIS instance (one committed F128
    // element per witness element) before any parameter-derived structure
    // is built. See [`VerifyError::ParamsMismatch`].
    if commitment.params.m != r1cs.m + pcs::LOG_PACKING
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }

    // ---- Bind the FS transcript to the statement (mirrors prove_field).
    crate::proof::bind_statement_field(challenger, r1cs, commitment);

    // ---- Public-IO envelope binding (mirrors prove_field_with_public_io).
    let io_claims: Vec<pcs::QuirkyDirectClaim> = match public_io {
        Some((spec, io)) => crate::public_io::bind_public_io(challenger, spec, io, r1cs.m),
        None => Vec::new(),
    };
    let auxiliary_claims = post_commit(commitment, challenger)?;

    // ---- Field zerocheck.
    let zc_claim = zerocheck::field::verify(r1cs.m, &proof.zerocheck, challenger)
        .map_err(VerifyError::Zerocheck)?;

    // ---- Lincheck (shared verify; witness semantics enter via the circuit).
    let inner_rest_len = r1cs.k_log - r1cs.k_skip;
    let x_ab = QuirkyPoint {
        z_skip: zc_claim.z,
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    // The canonical statement is already resident as dictionary-encoded CSR.
    // Fold directly from those rows: materializing the derived CSC transpose
    // here would retain a second full matrix representation on every loaded
    // production verifier class. `FieldRowCircuit` computes the exact same
    // `comb_vec`, hence leaves every transcript challenge and acceptance
    // decision unchanged.
    let row_circuit = crate::field_r1cs::FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
    let lc_claim = lincheck::verify(
        r1cs.m,
        r1cs.k_log,
        r1cs.k_skip,
        &row_circuit,
        &x_ab,
        zc_claim.a_eval,
        zc_claim.b_eval,
        &proof.lincheck,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;

    // ---- The two z-claims (must match what prove_field returned).
    let ab = ZClaim {
        point: QuirkyPoint {
            z_skip: lc_claim.r_inner_skip,
            x_inner_rest: lc_claim.r_inner_rest.clone(),
            x_outer: x_ab.x_outer.clone(),
        },
        value: lc_claim.w,
    };
    let c = ZClaim {
        point: QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zc_claim.c_eval,
    };

    // ---- Batched quirky-direct PCS opening over both claims.
    let x_rest_of = |zc: &ZClaim| -> Vec<F128> {
        let mut v = zc.point.x_inner_rest.clone();
        v.extend_from_slice(&zc.point.x_outer);
        v
    };
    let ab_rest = x_rest_of(&ab);
    let c_rest = x_rest_of(&c);
    let mut refs = vec![
        pcs::QuirkyDirectClaimRef {
            z_skip: ab.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: &ab_rest,
            value: ab.value,
        },
        pcs::QuirkyDirectClaimRef {
            z_skip: c.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: &c_rest,
            value: c.value,
        },
    ];
    refs.extend(io_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    refs.extend(auxiliary_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    pcs::verify_opening_batch_quirky_direct(commitment, &refs, &proof.pcs_open, challenger)
        .map_err(VerifyError::PcsAb)?;

    Ok(R1csClaim { ab, c })
}

#[cfg(test)]
mod tests {
    use crate::field_r1cs::{FieldRowCircuit, synthetic_satisfiable};

    /// Every individual verifier remains single-threaded even though two
    /// independent calls may occupy the bounded lane set concurrently.
    ///
    /// (The end-to-end prove → verify roundtrip and tamper-rejection tests live
    /// in `noid-ivc-prover`'s `tests/verifier_roundtrip.rs`, since they need the
    /// prove path.)
    #[test]
    fn each_verifier_lane_is_single_threaded() {
        let pools = super::VerifierPools::new();
        let n = pools.install(rayon::current_num_threads);
        assert_eq!(n, 1, "each verifier lane must have exactly one worker");
    }

    #[test]
    fn verifier_lanes_admit_two_calls_and_bound_the_third() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let pools = std::sync::Arc::new(super::VerifierPools::new());
        let entered = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let first_two_entered = Arc::new(Barrier::new(3));
        let release_first_two = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..3 {
            let pools = Arc::clone(&pools);
            let entered = Arc::clone(&entered);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let first_two_entered = Arc::clone(&first_two_entered);
            let release_first_two = Arc::clone(&release_first_two);
            workers.push(std::thread::spawn(move || {
                pools.install(|| {
                    assert_eq!(rayon::current_num_threads(), 1);
                    let ticket = entered.fetch_add(1, Ordering::AcqRel);
                    let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                    peak.fetch_max(now, Ordering::AcqRel);
                    if ticket < 2 {
                        first_two_entered.wait();
                        release_first_two.wait();
                    }
                    active.fetch_sub(1, Ordering::AcqRel);
                });
            }));
        }

        first_two_entered.wait();
        assert_eq!(entered.load(Ordering::Acquire), 2);
        assert_eq!(active.load(Ordering::Acquire), 2);
        release_first_two.wait();
        for worker in workers {
            worker.join().expect("bounded verifier worker");
        }
        assert_eq!(entered.load(Ordering::Acquire), 3);
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(peak.load(Ordering::Acquire), 2);
    }

    #[test]
    fn cross_rayon_pool_caller_cannot_retain_completed_lane_leases() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Condvar, Mutex, mpsc};
        use std::time::Duration;

        let pools = Arc::new(super::VerifierPools::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let entered = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        *pools.wait_observer.lock().unwrap() = Some(waiting_tx);

        let runner_pools = Arc::clone(&pools);
        let runner_release = Arc::clone(&release);
        let runner_entered = Arc::clone(&entered);
        let runner = std::thread::spawn(move || {
            let caller_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .expect("build cross-pool verifier caller");
            caller_pool.install(move || {
                rayon::scope(|scope| {
                    for _ in 0..3 {
                        let pools = Arc::clone(&runner_pools);
                        let release = Arc::clone(&runner_release);
                        let entered = Arc::clone(&runner_entered);
                        let entered_tx = entered_tx.clone();
                        scope.spawn(move |_| {
                            pools.install(move || {
                                let ticket = entered.fetch_add(1, Ordering::AcqRel);
                                if ticket < 2 {
                                    let _ = entered_tx.send(ticket);
                                    let (released, available) = &*release;
                                    let mut released = released.lock().unwrap();
                                    while !*released {
                                        released = available.wait(released).unwrap();
                                    }
                                }
                            });
                        });
                    }
                });
            });
            let _ = done_tx.send(());
        });

        let timeout = Duration::from_secs(5);
        let first_two_entered =
            entered_rx.recv_timeout(timeout).is_ok() && entered_rx.recv_timeout(timeout).is_ok();
        // `acquire` emits this only while all lanes are busy and immediately
        // before the third install atomically releases `busy` in Condvar::wait.
        // Waiting for it makes the old caller-owned-lease deadlock deterministic.
        let third_is_waiting = waiting_rx.recv_timeout(timeout).is_ok();
        // Always release any lane closures that did enter, even if the setup
        // assertion failed, so this regression cannot strand its own workers.
        {
            let (released, available) = &*release;
            *released.lock().unwrap() = true;
            available.notify_all();
        }

        let completed = done_rx.recv_timeout(timeout).is_ok();
        if !completed {
            // Cleanup for the exact old failure mode: its completed lane jobs
            // left both permits on the blocked caller's nested stack.  Waking
            // the third install lets the detached Rayon stack unwind, so a
            // regression fails by assertion rather than hanging the test run.
            let mut busy = pools.busy.lock().unwrap();
            busy.fill(false);
            pools.available.notify_all();
        }
        let joined = runner.join();

        assert!(first_two_entered, "two verifier lanes did not overlap");
        assert!(third_is_waiting, "third verifier install did not wait");
        assert!(
            completed,
            "completed lane jobs retained their leases on a cross-pool caller"
        );
        joined.expect("cross-pool verifier caller");
        assert_eq!(entered.load(Ordering::Acquire), 3);
    }

    #[test]
    fn verifier_lane_is_reentrant_and_panic_releases_lease() {
        let pools = super::VerifierPools::new();
        let (outer, inner) = pools.install(|| {
            let outer = super::ACTIVE_VERIFIER_LANE
                .with(std::cell::Cell::get)
                .expect("outer verifier lane");
            let inner = pools.install(|| {
                super::ACTIVE_VERIFIER_LANE
                    .with(std::cell::Cell::get)
                    .expect("nested verifier lane")
            });
            (outer.lane, inner.lane)
        });
        assert_eq!(outer, inner, "nested verifier must reuse its lane");

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pools.install(|| panic!("synthetic verifier panic"));
        }));
        assert!(panic.is_err());
        assert_eq!(pools.install(|| 7), 7, "panic leaked a verifier lease");
    }

    /// Production field verification must borrow the canonical CSR matrices;
    /// constructing its circuit may not populate the retained CSC cache.
    #[test]
    fn field_verifier_circuit_is_borrowing_and_csc_free() {
        let (r1cs, _) = synthetic_satisfiable(8, 6, 0xC5C0_FEEE);
        assert!(r1cs.csc_cache.get().is_none());

        let circuit = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
        assert_eq!(
            crate::lincheck::LincheckCircuit::n_cols(&circuit),
            1usize << r1cs.k_log,
        );
        assert!(
            r1cs.csc_cache.get().is_none(),
            "borrowing verifier circuit unexpectedly retained a CSC transpose",
        );
    }

    /// Structural regression guard: the production verifier source must not
    /// regain either lazy or direct CSC construction. The end-to-end fold and
    /// transcript parity is covered in `field_r1cs` tests.
    #[test]
    fn production_field_verifier_source_contains_no_csc_construction() {
        let production = include_str!("verifier.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("verifier has a production section");
        assert!(!production.contains(".csc_lincheck_circuit()"));
        assert!(!production.contains("FieldCscCircuit::from_matrices"));
    }
}
