// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Joint-bank terminal encoding. Public IO carries the immutable legacy
//! origin; the independently verified origin certificate remains mandatory.

use super::super::super::wire::{
    decode_f128_vec, decode_field_proof, encode_f128_vec, encode_field_proof, field_proof_len,
    Reader,
};
use super::*;
use crate::region_sidecar::{
    canonical_joint_c1_region_sidecar_len, decode_joint_c1_region_sidecar_canonical,
    encode_joint_c1_region_sidecar_canonical,
};

mod compression;

pub const TERMINAL_VERSION: u8 = noid_chain::history_step::HISTORY_STEP_TERMINAL_V2_VERSION;
const PREFIX: usize = 42;

pub fn terminal_max_bytes(runtime: &Runtime, class: Class) -> Result<usize, V2Error> {
    let config = runtime.bank.config().class(class);
    Ok(PREFIX
        + 32
        + IO_LEN * 16
        + field_proof_len(config.shape(), &config.pcs_params())?
        + canonical_joint_c1_region_sidecar_len(
            &runtime.parts.parent_vk,
            runtime.parts.block_vk(class),
            config.outer_m(),
        )?)
}

pub fn encode_terminal(runtime: &Runtime, terminal: &Terminal) -> Result<Vec<u8>, V2Error> {
    let class = terminal.class;
    let config = runtime.bank.config().class(class);
    let parsed = runtime.bank.parse(&terminal.proof.io)?;
    if parsed.class != class {
        return Err(V2Error::Io);
    }
    parsed.origin.check(&runtime.bank)?;
    if pcs_params_statement_bytes(&terminal.proof.commitment.params)
        != pcs_params_statement_bytes(&config.pcs_params())
    {
        return Err(V2Error::Runtime);
    }
    let max = terminal_max_bytes(runtime, class)?;
    let mut out = Vec::with_capacity(max);
    out.push(TERMINAL_VERSION);
    out.extend_from_slice(&parsed.accumulator.height.to_le_bytes());
    out.extend_from_slice(&parsed.accumulator.tip_semantic_id);
    out.push(class.wire_id());
    out.extend_from_slice(&terminal.proof.commitment.root);
    encode_f128_vec(&mut out, &terminal.proof.io, IO_LEN)?;
    encode_field_proof(
        &mut out,
        &terminal.proof.field,
        config.shape(),
        &config.pcs_params(),
        true,
    )?;
    out.extend_from_slice(&encode_joint_c1_region_sidecar_canonical(
        &runtime.parts.parent_vk,
        runtime.parts.block_vk(class),
        config.outer_m(),
        &terminal.proof.sidecar,
    )?);
    if out.len() > max {
        return Err(V2Error::Io);
    }
    if let Some(packed) = compression::pack(&out[PREFIX + 32..]).map_err(|_| V2Error::Io)? {
        out.truncate(PREFIX + 32);
        out.extend_from_slice(&packed);
    }
    Ok(out)
}

/// Bounded decode is not acceptance. The caller must invoke `verify_terminal`
/// with an authenticated origin and the selected sealed header.
pub fn decode_terminal(runtime: &Runtime, bytes: &[u8]) -> Result<Terminal, V2Error> {
    let class = Class::from_wire(*bytes.get(41).ok_or(V2Error::Io)?)?;
    let config = runtime.bank.config().class(class);
    if bytes.len() < PREFIX + 33
        || bytes.len() > terminal_max_bytes(runtime, class)?
        || bytes[0] != TERMINAL_VERSION
    {
        return Err(V2Error::Io);
    }
    let height = u64::from_le_bytes(bytes[1..9].try_into().map_err(|_| V2Error::Io)?);
    if height < runtime.bank.config().activation_height() {
        return Err(V2Error::Boundary);
    }
    let root = bytes[PREFIX..PREFIX + 32]
        .try_into()
        .map_err(|_| V2Error::Io)?;
    // BASE is a canonical field boolean, so its first byte cannot be 0xff.
    let payload = compression::unpack(
        &bytes[PREFIX + 32..],
        terminal_max_bytes(runtime, class)? - PREFIX - 32,
    )
    .map_err(|_| V2Error::Io)?;
    let mut reader = Reader::new(&payload);
    let io = decode_f128_vec(&mut reader, IO_LEN)?;
    // Reject a forged origin or metadata before proof allocations and PCS work.
    let parsed = runtime.bank.parse(&io)?;
    parsed.origin.check(&runtime.bank)?;
    if parsed.class != class
        || height != parsed.accumulator.height
        || bytes[9..41] != parsed.accumulator.tip_semantic_id
    {
        return Err(V2Error::Boundary);
    }
    let field = decode_field_proof(&mut reader, config.shape(), &config.pcs_params(), true)?;
    let len = canonical_joint_c1_region_sidecar_len(
        &runtime.parts.parent_vk,
        runtime.parts.block_vk(class),
        config.outer_m(),
    )?;
    let sidecar = decode_joint_c1_region_sidecar_canonical(
        &runtime.parts.parent_vk,
        runtime.parts.block_vk(class),
        config.outer_m(),
        reader.take(len)?,
    )?;
    reader.finish()?;
    Ok(Terminal {
        class,
        proof: V2Proof {
            field,
            commitment: Commitment {
                root,
                params: config.pcs_params(),
            },
            io,
            sidecar,
        },
    })
}
