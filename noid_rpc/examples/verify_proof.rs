// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Verify RPC Merkle proofs against a header already authenticated by the client.

use std::error::Error;
use std::path::Path;

use noid_chain::{exact_state_hash::slot_leaf_hash, fri_state::SlotValue, sparse_merkle};
use noid_poseidon2b::primitives::Address;
use noid_rpc::types::{BlockHeaderInfo, SlotProofInfo};
use serde::de::DeserializeOwned;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn read<T: DeserializeOwned>(path: &str) -> Result<T> {
    if Path::new(path).metadata()?.len() > 1024 * 1024 {
        return Err("proof/header JSON exceeds one MiB".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    if value.get("error").is_some() {
        return Err("JSON-RPC response contains an error".into());
    }
    Ok(serde_json::from_value(
        value.get("result").cloned().unwrap_or(value),
    )?)
}

fn digest(value: &str) -> Result<[u8; 32]> {
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "digest must contain 32 bytes")?)
}

fn boundary(height: u64, hash: &str, header: &BlockHeaderInfo) -> Result<()> {
    if height != header.height || digest(hash)? != digest(&header.hash)? {
        return Err("proof belongs to a different canonical header".into());
    }
    Ok(())
}

fn verify_slots(proof: SlotProofInfo, header: &BlockHeaderInfo, wanted: &str) -> Result<()> {
    boundary(proof.height, &proof.block_hash, header)?;
    if proof.log_slots != header.log_slots
        || digest(&proof.state_root)? != digest(&header.state_root)?
    {
        return Err("proof State boundary differs from the authenticated header".into());
    }
    let indices = wanted
        .split(',')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if indices
        != proof
            .slots
            .iter()
            .map(|slot| slot.slot_index)
            .collect::<Vec<_>>()
    {
        return Err("proof slots differ from the requested indices".into());
    }
    let mut leaves = Vec::with_capacity(proof.slots.len());
    for slot in &proof.slots {
        let owner = if slot.empty {
            if slot.value != 0 || slot.creation_id != 0 || !slot.owner.is_empty() {
                return Err("empty slot has nonzero fields".into());
            }
            Address([0; 32])
        } else {
            Address::parse(&slot.owner).map_err(|e| format!("slot owner: {e}"))?
        };
        let value = SlotValue::with_owner_fields(slot.value, slot.creation_id, owner.as_fields());
        if (value == SlotValue::EMPTY) != slot.empty {
            return Err("slot empty flag mismatch".into());
        }
        leaves.push(slot_leaf_hash(value));
    }
    let siblings = proof
        .siblings
        .iter()
        .map(|hash| digest(hash))
        .collect::<Result<Vec<_>>>()?;
    let root = sparse_merkle::reconstruct_root(&indices, &leaves, &siblings, proof.log_slots)?;
    if root != digest(&header.state_root)? {
        return Err("slot proof root mismatch".into());
    }
    println!(
        "Verified {} slots at block {}",
        indices.len(),
        header.height
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: verify_proof PROOF.json AUTHENTICATED_HEADER.json INDICES_CSV".into());
    }
    let header: BlockHeaderInfo = read(&args[1])?;
    verify_slots(read(&args[0])?, &header, &args[2])
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
