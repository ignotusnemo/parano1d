// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

/// Owner construction selected by the candidate block's consensus rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OwnerAuthorizationVersion {
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl OwnerAuthorizationVersion {
    pub const fn construction_version(self) -> u128 {
        self as u8 as u128
    }

    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            5 => Some(Self::V5),
            _ => None,
        }
    }

    pub const fn uses_v4_hiding(self) -> bool {
        matches!(self, Self::V4 | Self::V5)
    }

    pub const fn proof_node_hash_version(self) -> noid_poseidon2b::native::ProofNodeHashVersion {
        match self {
            Self::V3 | Self::V4 => noid_poseidon2b::native::ProofNodeHashVersion::FeedForward,
            Self::V5 => noid_poseidon2b::native::ProofNodeHashVersion::FixedCapacity,
        }
    }
}
