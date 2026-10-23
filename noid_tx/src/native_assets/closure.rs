// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact content-addressed closures for native carriers and header operands.

use std::collections::{BTreeMap, BTreeSet};

use noid_poseidon2b::primitives::Address;

use super::{NativeAssetError, NativeOpening};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeClosureError {
    Bounds,
    Missing(Address),
    Root(Address),
    Carrier(Address),
    Extraneous,
    Opening(NativeAssetError),
}
impl core::fmt::Display for NativeClosureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native closure: {self:?}")
    }
}
impl std::error::Error for NativeClosureError {}

fn fetch(
    root: Address,
    records: &mut BTreeMap<[u8; 32], NativeOpening>,
    limit: usize,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<NativeOpening, NativeClosureError> {
    if let Some(&value) = records.get(&root.0) {
        return Ok(value);
    }
    if records.len() >= limit {
        return Err(NativeClosureError::Bounds);
    }
    let value = resolve(root).ok_or(NativeClosureError::Missing(root))?;
    value.validate().map_err(NativeClosureError::Opening)?;
    if value.root() != root {
        return Err(NativeClosureError::Root(root));
    }
    records.insert(root.0, value);
    Ok(value)
}

/// Carrier roots represent raw State actions. Operand roots are committed
/// read objects or definitions. Each live object has at most one auxiliary
/// definition, whose class and identifier are checked by the shared schema.
pub fn resolve_native_closure(
    carriers: &[Address],
    operands: &[Address],
    limit: usize,
    mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<Vec<NativeOpening>, NativeClosureError> {
    let carrier_keys: BTreeSet<_> = carriers.iter().map(|r| r.0).collect();
    let keys: BTreeSet<_> = carrier_keys
        .iter()
        .copied()
        .chain(operands.iter().map(|r| r.0))
        .collect();
    if keys.len() > limit {
        return Err(NativeClosureError::Bounds);
    }
    let mut records = BTreeMap::new();
    for key in keys {
        let value = fetch(Address(key), &mut records, limit, &mut resolve)?;
        if carrier_keys.contains(&key) && value.is_auxiliary() {
            return Err(NativeClosureError::Carrier(Address(key)));
        }
        let dependency = value
            .dependency_root()
            .map(|root| fetch(root, &mut records, limit, &mut resolve))
            .transpose()?;
        value
            .check_dependency(dependency)
            .map_err(NativeClosureError::Opening)?;
    }
    Ok(records.into_values().collect())
}

pub fn canonical_native_closure(
    carriers: &[Address],
    operands: &[Address],
    supplied: &[NativeOpening],
    limit: usize,
) -> Result<Vec<NativeOpening>, NativeClosureError> {
    if supplied.len() > limit {
        return Err(NativeClosureError::Bounds);
    }
    let mut keyed = BTreeMap::new();
    for &opening in supplied {
        if keyed
            .insert(opening.root().0, opening)
            .is_some_and(|old| old != opening)
        {
            return Err(NativeClosureError::Extraneous);
        }
    }
    let closure = resolve_native_closure(carriers, operands, limit, |r| keyed.get(&r.0).copied())?;
    if closure.len() != keyed.len() {
        return Err(NativeClosureError::Extraneous);
    }
    Ok(closure)
}
