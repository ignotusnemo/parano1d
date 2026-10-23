// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native launch, permanent-pool and fixed-price marketplace profile.

use super::NativeKind;

pub const fn operation_enabled(code: u16) -> bool {
    matches!(
        code,
        2 | 3
            | 5
            | 6
            | 7
            | 8
            | 33
            | 38
            | 39
            | 40
            | 41
            | 43
            | 48
            | 49
            | 50
            | 51
            | 52
            | 53
            | 64
            | 65
            | 66
            | 80
    )
}

pub const fn kind_enabled(kind: NativeKind) -> bool {
    matches!(
        kind,
        NativeKind::FungibleDefinition
            | NativeKind::TokenBalance
            | NativeKind::TokenReserve
            | NativeKind::NftCollection
            | NativeKind::NftItem
            | NativeKind::MarketDefinition
            | NativeKind::MarketPool
            | NativeKind::MarketRequest
            | NativeKind::MarketClaim
            | NativeKind::LaunchDefinition
            | NativeKind::LaunchState
            | NativeKind::LaunchRequest
            | NativeKind::NftListingDefinition
            | NativeKind::NftListing
    )
}

pub const fn sequential_kind_enabled(kind: NativeKind) -> bool {
    matches!(
        kind,
        NativeKind::FungibleDefinition
            | NativeKind::TokenBalance
            | NativeKind::TokenReserve
            | NativeKind::NftCollection
            | NativeKind::NftItem
            | NativeKind::MarketDefinition
            | NativeKind::MarketPool
            | NativeKind::LaunchDefinition
            | NativeKind::LaunchState
            | NativeKind::NftListingDefinition
            | NativeKind::NftListing
    )
}
