// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Three proof classes sharing an authenticated authorization boundary.
//! Each matrix verifies the selected predecessor and preserves all carried
//! matrix obligations across class changes.

use super::*;
use noid_ivc_core::field_circuit::f128_from_u128;
mod assembly;
mod authorization_origin;
mod bank;
mod config;
mod decision;
mod parent;
mod shared_parent;
mod wire;
pub use assembly::{
    assemble_frozen, derive_assembled_block_vk, prepare_for_pow, prove_built, Built, PreparedForPow,
};
pub use authorization_origin::{AuthorizationOriginCertificate, MAX_AUTHORIZATION_ORIGIN_BYTES};
use bank::install_claim;
pub use bank::{Bank, Origin, VerifiedOrigin};
pub use config::{Class, Config};
use config::{
    Lane, ACC, BANK, BASE, IO_LEN, MATRIX, ORIGIN, ORIGIN_ACC, ORIGIN_ID, POINT, POST, TIP_CLASS,
};
pub use decision::{verify_terminal, AcceptedTerminal};
pub use wire::{decode_terminal, encode_terminal, terminal_max_bytes, TERMINAL_VERSION};

const PROOF_DOMAIN: &[u8] = b"history-step-banked-v2";
const FOLD_DOMAIN: &[u8] = b"history-step-banked-fold-v2";
const ROUTE_DOMAIN: &[u8] = b"history-step-banked-route-v2";

#[derive(Clone, Debug)]
pub struct RuntimeParts {
    config: Config,
    parent_vk: LinkRegionSidecarVk,
    block_vks: [BlockRegionSidecarVk; 3],
    child_layouts: [DuplexLayout; 3],
    parent_layouts: [DuplexLayout; 3],
    geometry: HistoryStepParentGeometry,
}
impl RuntimeParts {
    pub fn new(
        config: Config,
        block_vks: [BlockRegionSidecarVk; 3],
        child_layouts: [DuplexLayout; 3],
        parent_layouts: [DuplexLayout; 3],
    ) -> Result<Self, V2Error> {
        for class in Class::ALL {
            let vk = &block_vks[class.index()];
            if !vk.supports_objects()
                || vk.version() != crate::region_sidecar::BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION
                || *vk
                    != BlockRegionSidecarVk::from_object_registry_slices(
                        config.class(class).block_geometry(),
                        vk.selected_registry_slices()?,
                    )?
            {
                return Err(V2Error::Runtime);
            }
        }
        let geometry = HistoryStepParentGeometry::three_classes(
            &Class::ALL.map(|c| config.class(c).pcs_params()),
            child_layouts.to_vec(),
            parent_layouts.to_vec(),
        )?;
        let parent_vk = geometry.canonical_vk(&config.io_spec())?;
        Ok(Self {
            config,
            parent_vk,
            block_vks,
            child_layouts,
            parent_layouts,
            geometry,
        })
    }
    pub fn config(&self) -> Config {
        self.config
    }
    pub fn parent_vk(&self) -> &LinkRegionSidecarVk {
        &self.parent_vk
    }
    pub fn block_vk(&self, class: Class) -> &BlockRegionSidecarVk {
        &self.block_vks[class.index()]
    }
    pub fn child_layout(&self, class: Class) -> &DuplexLayout {
        &self.child_layouts[class.index()]
    }
    pub fn parent_layout(&self, class: Class) -> &DuplexLayout {
        &self.parent_layouts[class.index()]
    }
}

pub trait MatrixSource: Send + Sync {
    fn load(&self, class: Class) -> Result<HistoryStepMatrixLease, V2Error>;
}

pub struct Runtime {
    bank: Bank,
    parts: RuntimeParts,
    matrices: Box<dyn MatrixSource>,
    cache: decision::ClaimCache,
}
impl Runtime {
    pub fn new(
        bank: Bank,
        parts: RuntimeParts,
        matrices: Box<dyn MatrixSource>,
    ) -> Result<Self, V2Error> {
        bank.check_parts(&parts)?;
        Ok(Self {
            bank,
            parts,
            matrices,
            cache: Default::default(),
        })
    }
    pub fn bank(&self) -> &Bank {
        &self.bank
    }
    pub fn parts(&self) -> &RuntimeParts {
        &self.parts
    }
    /// Warm the source's authenticated artifact cache before mining. This
    /// grants no terminal authority and never skips matrix authentication.
    pub fn prepare_matrix_cache(&self, class: Class) -> Result<(), V2Error> {
        self.load_matrix(class).map(drop)
    }
    fn load_matrix(&self, class: Class) -> Result<HistoryStepMatrixLease, V2Error> {
        let matrix = self.matrices.load(class)?;
        self.bank.authenticate(class, &matrix)?;
        Ok(matrix)
    }
}
struct NoMatrix;
impl MatrixSource for NoMatrix {
    fn load(&self, _: Class) -> Result<HistoryStepMatrixLease, V2Error> {
        Err(V2Error::Matrix)
    }
}

pub fn derive_runtime_parts(
    config: Config,
    block_vks: [BlockRegionSidecarVk; 3],
) -> Result<RuntimeParts, V2Error> {
    let mut children = std::array::from_fn(|_| placeholder_history_step_recording_layout(1 << 14));
    let mut parents = children.clone();
    for _ in 0..16 {
        let parts =
            RuntimeParts::new(config, block_vks.clone(), children.clone(), parents.clone())?;
        let runtime = Runtime::new(
            Bank::pin([[0; 32]; 3], &parts),
            parts.clone(),
            Box::new(NoMatrix),
        )?;
        let mut next_children = Vec::new();
        let mut next_parents = Vec::new();
        for class in Class::ALL {
            let (_, scratch) = parent::shape_only_arm(&runtime, class, vec![F128::ZERO; IO_LEN])?;
            next_children.push(scratch.child.layout);
            next_parents.push(scratch.parent.layout);
        }
        if next_children.as_slice() == children && next_parents.as_slice() == parents {
            return Ok(parts);
        }
        children = next_children.try_into().map_err(|_| V2Error::Layout)?;
        parents = next_parents.try_into().map_err(|_| V2Error::Layout)?;
    }
    Err(V2Error::Layout)
}

/// Persisted bytes are not acceptance authority. Verification also requires
/// the independently authenticated legacy boundary and both matrix lanes.
pub struct Terminal {
    class: Class,
    proof: V2Proof,
}
impl Terminal {
    pub fn class(&self) -> Class {
        self.class
    }
    pub fn claimed_origin(&self, runtime: &Runtime) -> Result<Origin, V2Error> {
        let parsed = runtime.bank.parse(&self.proof.io)?;
        if parsed.class != self.class {
            return Err(V2Error::Io);
        }
        Ok(parsed.origin)
    }
    pub fn accumulator(&self, bank: &Bank) -> Result<ChainAccumulator, V2Error> {
        let parsed = bank.parse(&self.proof.io)?;
        if parsed.class != self.class {
            return Err(V2Error::Io);
        }
        Ok(parsed.accumulator)
    }
}
