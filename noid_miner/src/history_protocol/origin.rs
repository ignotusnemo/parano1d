// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_recursive::acceptance::history_step::v2::{banked as v2, capacity_banked as v21, V2Error};
use noid_recursive::ChainAccumulator;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkOrigin {
    V2(v2::Origin),
    V21(v21::Origin),
}

impl From<v2::Origin> for ForkOrigin {
    fn from(origin: v2::Origin) -> Self {
        Self::V2(origin)
    }
}
impl From<v21::Origin> for ForkOrigin {
    fn from(origin: v21::Origin) -> Self {
        Self::V21(origin)
    }
}
impl ForkOrigin {
    pub fn boundary(&self) -> &ChainAccumulator {
        match self {
            Self::V2(origin) => origin.boundary(),
            Self::V21(origin) => origin.boundary(),
        }
    }
    pub fn parent_id(&self) -> [u8; 32] {
        match self {
            Self::V2(origin) => origin.parent_id(),
            Self::V21(origin) => origin.parent_id(),
        }
    }
    pub fn request_binding(&self) -> [u8; 32] {
        match self {
            Self::V2(origin) => origin.request_binding(),
            Self::V21(origin) => origin.request_binding(),
        }
    }
    pub fn next_bank(&self) -> [u8; 32] {
        match self {
            Self::V2(origin) => origin.next_bank(),
            Self::V21(origin) => origin.next_bank(),
        }
    }
    pub fn activation_height(&self) -> Result<u64, V2Error> {
        match self {
            Self::V2(origin) => origin.activation_height(),
            Self::V21(origin) => origin.activation_height(),
        }
    }
}

enum VerifiedKind {
    V2(v2::VerifiedOrigin),
    V21(v21::VerifiedOrigin),
}

pub struct VerifiedForkOrigin {
    origin: ForkOrigin,
    checked: VerifiedKind,
}

impl VerifiedForkOrigin {
    pub(super) fn from_v2(checked: v2::VerifiedOrigin) -> Self {
        Self {
            origin: checked.origin().clone().into(),
            checked: VerifiedKind::V2(checked),
        }
    }
    pub(super) fn from_v21(checked: v21::VerifiedOrigin) -> Self {
        Self {
            origin: checked.origin().clone().into(),
            checked: VerifiedKind::V21(checked),
        }
    }
    pub fn origin(&self) -> &ForkOrigin {
        &self.origin
    }
    pub fn v2(&self) -> Result<&v2::VerifiedOrigin, String> {
        match &self.checked {
            VerifiedKind::V2(checked) => Ok(checked),
            VerifiedKind::V21(_) => Err("fork origin belongs to the three-class bank".into()),
        }
    }
    pub fn v21(&self) -> Result<&v21::VerifiedOrigin, String> {
        match &self.checked {
            VerifiedKind::V21(checked) => Ok(checked),
            VerifiedKind::V2(_) => Err("fork origin belongs to the two-class bank".into()),
        }
    }
}
