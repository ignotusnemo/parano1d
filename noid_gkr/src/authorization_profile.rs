// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

pub use noid_tx::OwnerAuthorizationVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationLayout {
    pub version: OwnerAuthorizationVersion,
    pub libra_len: usize,
    pub terminal_offset: usize,
    pub terminal_pad_groups: usize,
}

impl AuthorizationLayout {
    pub const fn for_version(version: OwnerAuthorizationVersion) -> Self {
        match version {
            OwnerAuthorizationVersion::V3 => Self {
                version,
                libra_len: 256,
                terminal_offset: 768,
                terminal_pad_groups: 1,
            },
            OwnerAuthorizationVersion::V4 => Self {
                version,
                libra_len: 432,
                terminal_offset: 944,
                terminal_pad_groups: 2,
            },
        }
    }

    pub const fn terminal_pad_cells(self) -> usize {
        5 * self.terminal_pad_groups
    }
}
