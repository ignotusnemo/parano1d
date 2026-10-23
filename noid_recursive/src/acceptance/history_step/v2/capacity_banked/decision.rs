// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use noid_ivc_core::matrix_claim::c1::{fresh_claim_value_c1, stacked_matrix_mle_eval_c1};
use std::{collections::VecDeque, sync::Mutex};

/// Only this verifier can add entries, after an authenticated matrix scan.
/// It stores exact accumulated claims, never acceptance of a whole terminal.
#[derive(Default)]
pub(super) struct ClaimCache(Mutex<VecDeque<CheckedClaim>>);
struct CheckedClaim {
    bank: [u8; 32],
    class: Class,
    matrix: [u8; 32],
    shape: FieldShape,
    claim: C1MatrixAccClaim,
}
impl ClaimCache {
    fn contains(&self, bank: &Bank, class: Class, claim: &C1MatrixAccClaim) -> bool {
        let Ok(mut entries) = self.0.lock() else {
            return false;
        };
        let Some(index) = entries.iter().position(|e| {
            e.bank == bank.digest()
                && e.class == class
                && e.matrix == bank.matrix_digest(class)
                && e.shape == bank.config().class(class).shape()
                && e.claim == *claim
        }) else {
            return false;
        };
        let found = entries.remove(index).expect("located checked claim");
        entries.push_back(found);
        true
    }
    fn remember(&self, bank: &Bank, class: Class, claim: C1MatrixAccClaim) {
        let Ok(mut entries) = self.0.lock() else {
            return;
        };
        if entries.len() == 8 {
            entries.pop_front();
        }
        entries.push_back(CheckedClaim {
            bank: bank.digest(),
            class,
            matrix: bank.matrix_digest(class),
            shape: bank.config().class(class).shape(),
            claim,
        });
    }
}

fn check_claims(
    matrix: &HistoryStepMatrixLease,
    fresh: Option<&C1FreshLincheckClaim>,
    accumulated: Option<&C1MatrixAccClaim>,
) -> Result<(), V2Error> {
    let (fv, av) = match matrix {
        HistoryStepMatrixLease::Resident(matrix) => (
            fresh.map(|claim| fresh_claim_value_c1(matrix, claim)),
            accumulated.map(|claim| stacked_matrix_mle_eval_c1(matrix, claim)),
        ),
        HistoryStepMatrixLease::Compact(matrix) => {
            let evaluated = matrix
                .evaluate_matrix_claims_c1_authenticated(fresh, accumulated)
                .map_err(|_| V2Error::Matrix)?;
            if !evaluated.is_bound_to(fresh, accumulated) {
                return Err(V2Error::Matrix);
            }
            (evaluated.fresh_value(), evaluated.accumulated_value())
        }
    };
    if fv != fresh.map(|c| c.value) || av != accumulated.map(|c| c.value) {
        return Err(V2Error::Matrix);
    }
    Ok(())
}

#[must_use = "verified v2 authority must be consumed by block application"]
pub struct AcceptedTerminal {
    class: Class,
    accumulator: ChainAccumulator,
    origin: Origin,
}
impl AcceptedTerminal {
    pub fn class(&self) -> Class {
        self.class
    }
    pub fn accumulator(&self) -> &ChainAccumulator {
        &self.accumulator
    }
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
}

pub fn verify_terminal(
    runtime: &Runtime,
    origin: &VerifiedOrigin,
    terminal: &Terminal,
    header: &BlockHeader,
    epoch_header: &BlockHeader,
) -> Result<AcceptedTerminal, V2Error> {
    origin.0.check(&runtime.bank)?;
    let parsed = runtime.bank.parse(&terminal.proof.io)?;
    if parsed.origin != origin.0 || parsed.class != terminal.class {
        return Err(V2Error::Origin);
    }
    parsed
        .accumulator
        .validate_local_header_boundary(header, epoch_header)
        .map_err(|_| V2Error::Boundary)?;
    let (fresh, _) = parent::replay(runtime, terminal.class, &terminal.proof)?;
    for class in Class::ALL {
        let current_fresh = (class == terminal.class).then_some(&fresh);
        let accumulated = parsed.claims[class.index()].as_ref();
        if current_fresh.is_none() {
            let Some(claim) = accumulated else {
                continue;
            };
            if runtime.cache.contains(&runtime.bank, class, claim) {
                continue;
            }
        }
        // Fresh claims are always scanned. Only an unchanged carried lane can
        // avoid reloading and scanning its matrix after an earlier success.
        let matrix = runtime.load_matrix(class)?;
        check_claims(&matrix, current_fresh, accumulated)?;
        if let Some(claim) = accumulated {
            runtime.cache.remember(&runtime.bank, class, claim.clone());
        }
    }
    Ok(AcceptedTerminal {
        class: parsed.class,
        accumulator: parsed.accumulator,
        origin: parsed.origin,
    })
}
