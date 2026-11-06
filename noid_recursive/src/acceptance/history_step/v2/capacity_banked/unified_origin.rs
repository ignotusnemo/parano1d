// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::super::banked as previous;
use super::*;
use crate::acceptance::history_step_bank::{
    retirement::{HistoryStepRetirementEvaluation, HistoryStepRetirementReduction},
    CanonicalHistoryStepClassId,
};
use noid_chain::fork_origin_carrier::UnifiedOriginCarrier;
use noid_ivc_core::matrix_claim::sparse_c1::SparseMatrixEvaluationProof;

#[derive(Clone, Debug)]
pub struct UnifiedOriginCertificate(UnifiedOriginCarrier);

fn error(e: impl core::fmt::Display) -> V2Error {
    V2Error::Retirement(e.to_string())
}

impl UnifiedOriginCertificate {
    pub fn new(
        authorization: &AuthorizationOriginCertificate,
        request: &crate::acceptance::history_step_bank::retirement::HistoryStepRetirementRequest,
        next: &Bank,
        reduction: &[u8],
        evaluations: &[(u8, Vec<u8>)],
    ) -> Result<Self, V2Error> {
        let origin = Origin::for_matrix_freezing(
            request.target().legacy_bank_digest(),
            next,
            request.parent_header(),
            request.epoch_anchor_header(),
            request.boundary(),
        )?;
        Ok(Self(
            UnifiedOriginCarrier::new(
                origin.request_binding(),
                &authorization.to_bytes(),
                reduction,
                evaluations,
            )
            .map_err(error)?,
        ))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, V2Error> {
        Ok(Self(
            UnifiedOriginCarrier::from_bytes(bytes).map_err(error)?,
        ))
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, V2Error> {
        self.0.to_bytes().map_err(error)
    }
    pub fn authorization(&self) -> Result<AuthorizationOriginCertificate, V2Error> {
        AuthorizationOriginCertificate::from_bytes(self.0.authorization_bytes())
    }
    pub fn predecessor_bytes(&self) -> &[u8] {
        self.0.predecessor_bytes()
    }
    pub fn predecessor_request(&self) -> [u8; 32] {
        self.0.predecessor_request()
    }
    pub fn claimed_request_binding(&self) -> [u8; 32] {
        self.0.request_binding()
    }
    pub fn with_predecessor_bytes(self, bytes: Vec<u8>) -> Result<Self, V2Error> {
        if self.predecessor_bytes() == bytes.as_slice() {
            return Ok(self);
        }
        let auth = self.authorization()?.with_previous_origin_bytes(bytes)?;
        let evaluations = self
            .0
            .evaluations()
            .map(|(c, p)| (c, p.to_vec()))
            .collect::<Vec<_>>();
        Ok(Self(
            UnifiedOriginCarrier::new(
                self.0.request_binding(),
                &auth.to_bytes(),
                self.0.reduction_bytes(),
                &evaluations,
            )
            .map_err(error)?,
        ))
    }

    /// The caller supplies the checked v1 -> v2 origin and independent release
    /// pins. Every live v2 matrix obligation is closed before returning.
    pub fn verify(
        &self,
        runtime: &previous::Runtime,
        predecessor: &previous::VerifiedOrigin,
        next: &Bank,
        keys: &previous::PinnedRetirementKeys,
    ) -> Result<VerifiedOrigin, V2Error> {
        let authorization = self.authorization()?;
        if authorization.previous_origin_request() != predecessor.origin().request_binding()
            || keys.legacy_bank_digest() != runtime.bank().digest()
        {
            return Err(V2Error::Origin);
        }
        let terminal = previous::decode_terminal(runtime, authorization.terminal_bytes())?;
        let request = previous::prepare_authorization_retirement(
            runtime,
            predecessor,
            &terminal,
            authorization.parent_header(),
            authorization.epoch_header(),
            next,
        )?;
        let reduction =
            HistoryStepRetirementReduction::decode_for(&request, self.0.reduction_bytes())
                .map_err(error)?;
        let pending = request.verify_reduction(&reduction).map_err(error)?;
        let encoded: Vec<_> = self.0.evaluations().collect();
        if pending.obligations().count() != encoded.len() {
            return Err(V2Error::Origin);
        }
        let mut proofs = Vec::with_capacity(encoded.len());
        for (claim, (class, bytes)) in pending.obligations().zip(&encoded) {
            if claim.class_id().wire_id() != *class {
                return Err(V2Error::Origin);
            }
            proofs.push(
                SparseMatrixEvaluationProof::from_bytes(
                    keys.key(claim.class_id()),
                    request.binding(),
                    claim.claim(),
                    bytes,
                )
                .map_err(error)?,
            );
        }
        let evaluations: Vec<_> = encoded
            .iter()
            .zip(&proofs)
            .map(|((class, _), proof)| {
                let class_id = CanonicalHistoryStepClassId::from_index(*class as usize).unwrap();
                HistoryStepRetirementEvaluation {
                    class_id,
                    key: keys.key(class_id),
                    proof,
                }
            })
            .collect();
        let checked = pending
            .verify_matrix_evaluations(&evaluations)
            .map_err(error)?;
        let origin = VerifiedOrigin::from_retirement(&request, checked, predecessor, next, keys)?;
        if origin.origin().request_binding() != self.0.request_binding() {
            return Err(V2Error::Origin);
        }
        Ok(origin)
    }
}
