// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

/// Owner construction selected by the candidate block's consensus rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OwnerAuthorizationVersion {
    V3 = 3,
    V4 = 4,
}

impl OwnerAuthorizationVersion {
    pub const fn construction_version(self) -> u128 {
        self as u8 as u128
    }

    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            _ => None,
        }
    }
}
