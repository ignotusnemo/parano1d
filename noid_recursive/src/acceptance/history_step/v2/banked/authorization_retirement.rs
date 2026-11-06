// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::super::capacity_banked;
use super::*;
use crate::acceptance::history_step_bank::{
    retirement::{HistoryStepRetirementRequest, HistoryStepRetirementTarget},
    CanonicalHistoryStepClassId,
};

/// Replay the exact predecessor terminal and retain every matrix obligation.
/// This operation never queries a matrix source or consults the claim cache.
pub fn prepare_authorization_retirement(
    previous: &Runtime,
    previous_origin: &VerifiedOrigin,
    terminal: &Terminal,
    parent_header: &BlockHeader,
    epoch_header: &BlockHeader,
    next: &capacity_banked::Bank,
) -> Result<HistoryStepRetirementRequest, V2Error> {
    let old = previous.bank().config();
    let new = next.config();
    if old.class(Class::Small).authorization_version() != noid_tx::OwnerAuthorizationVersion::V3
        || new
            .class(capacity_banked::Class::Small)
            .authorization_version()
            != noid_tx::OwnerAuthorizationVersion::V4
        || old.schedule() != new.schedule()
        || parent_header.height.checked_add(1) != Some(new.activation_height())
        || parent_header.height < old.activation_height()
    {
        return Err(V2Error::Boundary);
    }
    noid_chain::consensus::pow::validate_pow(parent_header).map_err(|_| V2Error::Origin)?;
    previous_origin.0.check(previous.bank())?;
    let parsed = previous.bank().parse(&terminal.proof.io)?;
    if parsed.origin != previous_origin.0 || parsed.class != terminal.class {
        return Err(V2Error::Origin);
    }
    let (fresh, _) = parent::replay(previous, terminal.class, &terminal.proof)?;
    let target = HistoryStepRetirementTarget::for_authorization(
        old.schedule(),
        previous.bank().digest(),
        next.digest(),
        new.activation_height(),
    )
    .map_err(|e| V2Error::Retirement(e.to_string()))?;
    HistoryStepRetirementRequest::from_banked_replay(
        target,
        previous_origin.origin().request_binding(),
        parent_header,
        epoch_header,
        parsed.accumulator,
        CanonicalHistoryStepClassId::from_index(parsed.class.index()).unwrap(),
        Class::ALL.map(|class| {
            (
                old.class(class).shape(),
                previous.bank().matrix_digest(class),
            )
        }),
        fresh,
        parsed.claims,
    )
    .map_err(|e| V2Error::Retirement(e.to_string()))
}
