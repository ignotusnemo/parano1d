// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The sole node-owned block-production path.
//!
//! Both the internal miner and `submitBlock(template_id, nonce)` prepare this
//! exact nonce-independent witness before PoW, then consume it once to prove
//! and atomically commit one [`noid_chain::AcceptedBlockBundle`].

use noid_chain::block::Block;
use noid_chain::consensus::pow::{block_id, validate_pow};
use noid_chain::storage::{MdbxChainContext, MdbxContextError};

use crate::template::BlockTemplate;

type HistoryStepRuntime = crate::HistoryProtocolRuntime;
type PreparedGhost =
    noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization;
type PreparedStateCommit = noid_chain::consensus::template::PreparedBlockStateCommit;
type LocallyProvedStateCommit = noid_chain::consensus::template::LocallyProvedBlockCommit;

enum PreparedWitness {
    B25(noid_block::PreparedHistoryStepWitness<25>),
    B255(noid_block::PreparedHistoryStepWitness<255>),
}

/// Mining class is height-selected. A small v2 block must never fall back to
/// the legacy B25/B255 rule just because it contains few physical pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningProofClass {
    Legacy(noid_chain::consensus::paged_spend::BlockProofClass),
    V2(noid_recursive::acceptance::history_step::v2::banked::Class),
    V21(noid_recursive::acceptance::history_step::v2::capacity_banked::Class),
}

/// A single-use, nonce-independent block witness prepared entirely by the
/// node. The external PoW worker never receives it and can change only nonce.
pub struct PreparedBlockAttempt {
    block: Block,
    terminal_bytes: Vec<u8>,
    end_accumulator: noid_recursive::ChainAccumulator,
    start_accumulator: noid_recursive::ChainAccumulator,
    parent_header: noid_chain::BlockHeader,
    expected_parent_id: [u8; 32],
    expected_parent_height: u64,
    payload_weight: usize,
    retained_bytes: usize,
    state_commit: PreparedStateCommit,
    proof_class: MiningProofClass,
}

/// A private-capability carrier created only after the HistoryStep prover has
/// successfully produced the exact terminal bundled with `block`.
pub struct ProvedBlock {
    local_commit: LocallyProvedStateCommit,
}

/// The same complete block after its bundle and public state transition have
/// been committed atomically to the canonical chain.
pub struct CommittedBlock {
    block: Block,
    bundle: noid_chain::AcceptedBlockBundle,
}

fn decode_template_authorizations(
    authorization_bytes: Vec<Option<Vec<u8>>>,
) -> Result<Vec<noid_gkr::zk_authorization::ZkAuthorizationProof>, String> {
    authorization_bytes
        .into_iter()
        .enumerate()
        .map(|(index, encoded)| {
            let encoded = encoded.ok_or_else(|| {
                format!("missing wallet authorization for user transaction {index}")
            })?;
            noid_gkr::WalletAuthorizationBundle::from_bytes(&encoded)
                .map(|bundle| bundle.proof)
                .map_err(|error| format!("wallet authorization {index} is not canonical: {error}"))
        })
        .collect()
}

fn accumulator_from_header_boundary(
    header: &noid_chain::BlockHeader,
    epoch_anchor_header: &noid_chain::BlockHeader,
) -> noid_recursive::ChainAccumulator {
    noid_recursive::ChainAccumulator {
        height: header.height,
        tip_semantic_id: noid_chain::block_header::semantic_header_id(header),
        state_root: header.state_root,
        log_slots: header.log_slots,
        active_slot_count: header.active_slot_count,
        alloc_counter: header.alloc_counter,
        epoch_anchor_id: block_id(epoch_anchor_header),
    }
}

impl PreparedBlockAttempt {
    /// Prepare every nonce-independent part of the next HistoryStep.
    pub fn prepare(
        template: BlockTemplate,
        runtime: &HistoryStepRuntime,
        ghost: &PreparedGhost,
        local_time: u64,
    ) -> Result<Self, String> {
        Self::prepare_inner(template, runtime, ghost, local_time, None)?.ok_or_else(|| {
            "uncancellable HistoryStep preparation was unexpectedly cancelled".to_string()
        })
    }

    /// Prepare a block while allowing a canonical-tip change to stop work at
    /// transcript-safe phase boundaries. `Ok(None)` is an expected local
    /// cancellation, not a proving failure.
    pub fn prepare_cancellable(
        template: BlockTemplate,
        runtime: &HistoryStepRuntime,
        ghost: &PreparedGhost,
        local_time: u64,
        cancellation: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<Self>, String> {
        Self::prepare_inner(template, runtime, ghost, local_time, Some(cancellation))
    }

    fn prepare_inner(
        template: BlockTemplate,
        runtime: &HistoryStepRuntime,
        ghost: &PreparedGhost,
        local_time: u64,
        cancellation: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Option<Self>, String> {
        let cancelled =
            || cancellation.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire));
        if cancelled() {
            return Ok(None);
        }
        let BlockTemplate {
            inner,
            parent,
            authorization_bytes,
            object_openings,
            native_openings,
            trade_batches,
            v2_class,
            v21_class,
            parent_state,
            finalized_active_counts,
            previous_timestamps,
            asert_anchor,
            parent_tx_epoch_anchor_header,
            parent_history_step_terminal_bytes,
            prepared_state_commit,
            ..
        } = template;

        let expected_parent_id = block_id(&parent);
        let expected_parent_height = parent.height;
        let authorization_weight = authorization_bytes
            .iter()
            .filter_map(|bytes| bytes.as_ref())
            .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
            .ok_or_else(|| "prepared authorization byte weight overflow".to_string())?;
        let authorization_proofs = decode_template_authorizations(authorization_bytes)?;
        if cancelled() {
            return Ok(None);
        }
        let start_accumulator =
            accumulator_from_header_boundary(&parent, &parent_tx_epoch_anchor_header);
        let block = inner.into_block(0);
        let native_weight = if native_openings.is_empty() {
            0
        } else {
            native_openings
                .len()
                .checked_mul(2 + noid_tx::native_assets::MAX_NATIVE_OPENING_BYTES)
                .and_then(|bytes| {
                    bytes.checked_add(noid_chain::block::payload::NATIVE_BODY_HEADER_BYTES)
                })
                .ok_or("prepared native record byte weight overflow")?
        };
        let trade_weight = trade_batches.iter().try_fold(0usize, |weight, batch| {
            let bytes = batch.to_bytes().map_err(|error| error.to_string())?;
            weight
                .checked_add(bytes.len())
                .ok_or_else(|| "prepared trade byte weight overflow".to_string())
        })?;
        let payload_weight = block
            .to_bytes()
            .len()
            .checked_add(authorization_weight)
            .and_then(|weight| weight.checked_add(native_weight))
            .and_then(|weight| weight.checked_add(trade_weight))
            .and_then(|weight| {
                object_openings
                    .len()
                    .checked_mul(noid_tx::experimental_object::OPENING_BYTES)
                    .and_then(|bytes| weight.checked_add(bytes))
            })
            .ok_or("prepared block byte weight overflow")?;
        let context = noid_block::HistoryStepPreparationContext {
            parent_header: &parent,
            tx_epoch_anchor_header: &parent_tx_epoch_anchor_header,
            parent_state: &parent_state,
            start_accumulator: &start_accumulator,
            previous_timestamps: &previous_timestamps,
            finalized_active_counts: &finalized_active_counts,
            asert_anchor: &asert_anchor,
            local_time,
        };
        if runtime.uses_finance_runtime(block.header.height) {
            use noid_recursive::acceptance::history_step::v2::capacity_banked as v21;
            if v2_class.is_some() {
                return Err("v2.1 template carries a different proof bank".into());
            }
            let class = v21_class.ok_or("v2.1 template has no explicit proof class")?;
            if class == v21::Class::Large && !runtime.large_v2_mining_allowed() {
                return Err("large v2.1 mining requires the server opt-in".into());
            }
            let parent_bytes = parent_history_step_terminal_bytes
                .as_deref()
                .ok_or("v2.1 parent terminal is missing")?;
            let origin =
                runtime.origin_for_parent(&parent, &parent_tx_epoch_anchor_header, parent_bytes)?;
            let ghost = runtime.authorization_ghost()?;
            let runtime = runtime.finance_at(block.header.height)?;
            let config = runtime.bank().config().class(class);
            let parent_terminal = if noid_chain::consensus::params::v2_1_active(parent.height) {
                Some(v21::decode_terminal(runtime, parent_bytes).map_err(|e| e.to_string())?)
            } else {
                None
            };
            if cancelled() {
                return Ok(None);
            }
            let end_accumulator = start_accumulator
                .advance(&parent, &block.header)
                .map_err(|e| format!("v2.1 accumulator transition: {e:?}"))?;
            macro_rules! prepare {
                ($pages:literal) => {{
                    let input =
                        noid_block::candidate_history::prepare_candidate_input_with_native_data::<
                            $pages,
                        >(
                            &block,
                            context,
                            authorization_proofs,
                            ghost.as_ref(),
                            &object_openings,
                            &native_openings,
                            &[],
                            &trade_batches,
                            config,
                        )
                        .map_err(|e| e.to_string())?;
                    if cancelled() {
                        return Ok(None);
                    }
                    v21::prepare_for_pow(
                        runtime,
                        class,
                        origin.v21()?.origin(),
                        parent_terminal.as_ref(),
                        input,
                    )
                    .map_err(|e| e.to_string())?
                }};
            }
            let prepared = match config.pages() {
                63 => prepare!(63),
                206 => prepare!(206),
                _ => {
                    return Err("v2.1 bank uses an unsupported producer page specialization".into())
                }
            };
            if cancelled() {
                return Ok(None);
            }
            let built = prepared.seal_nonce(runtime, 0).map_err(|e| e.to_string())?;
            let uncancelled = std::sync::atomic::AtomicBool::new(false);
            let terminal =
                match v21::prove_built(runtime, &built, cancellation.unwrap_or(&uncancelled)) {
                    Ok(terminal) => terminal,
                    Err(noid_recursive::acceptance::history_step::v2::V2Error::Cancelled) => {
                        return Ok(None)
                    }
                    Err(error) => return Err(error.to_string()),
                };
            if cancelled() {
                return Ok(None);
            }
            if terminal.class() != class {
                return Err("v2.1 proof class drifted from the selected template".into());
            }
            let terminal_bytes =
                v21::encode_terminal(runtime, &terminal).map_err(|e| e.to_string())?;
            let retained_bytes = payload_weight
                .checked_add(terminal_bytes.len())
                .ok_or("prepared v2.1 retained-byte weight overflow")?;
            return Ok(Some(Self {
                block,
                terminal_bytes,
                end_accumulator,
                start_accumulator,
                parent_header: parent,
                expected_parent_id,
                expected_parent_height,
                payload_weight,
                retained_bytes,
                state_commit: prepared_state_commit,
                proof_class: MiningProofClass::V21(class),
            }));
        }
        if noid_chain::consensus::params::v2_active(block.header.height) {
            use noid_recursive::acceptance::history_step::v2::banked as v2;
            if v21_class.is_some() {
                return Err("v2 template carries a different proof bank".into());
            }
            let class = v2_class.ok_or("v2 template has no explicit proof class")?;
            if class == v2::Class::Large && !runtime.large_v2_mining_allowed() {
                return Err("large v2 mining requires the server opt-in".into());
            }
            let parent_bytes = parent_history_step_terminal_bytes
                .as_deref()
                .ok_or("v2 parent terminal is missing")?;
            let origin =
                runtime.origin_for_parent(&parent, &parent_tx_epoch_anchor_header, parent_bytes)?;
            let updated_ghost;
            let ghost =
                if noid_chain::consensus::params::owner_authorization_version(block.header.height)
                    == noid_tx::OwnerAuthorizationVersion::V4
                {
                    updated_ghost = runtime.authorization_ghost()?;
                    updated_ghost.as_ref()
                } else {
                    ghost
                };
            let runtime = runtime.v2_at(block.header.height)?;
            let config = runtime.bank().config().class(class);
            let parent_terminal = if parent.height >= runtime.bank().config().activation_height() {
                Some(v2::decode_terminal(runtime, parent_bytes).map_err(|e| e.to_string())?)
            } else {
                None
            };
            if cancelled() {
                return Ok(None);
            }
            let end_accumulator = start_accumulator
                .advance(&parent, &block.header)
                .map_err(|e| format!("v2 accumulator transition: {e:?}"))?;
            macro_rules! prepare {
                ($pages:literal) => {{
                    let input =
                        noid_block::candidate_history::prepare_candidate_input_with_native_data::<
                            $pages,
                        >(
                            &block,
                            context,
                            authorization_proofs,
                            ghost,
                            &object_openings,
                            &native_openings,
                            &[],
                            &trade_batches,
                            config,
                        )
                        .map_err(|e| e.to_string())?;
                    if cancelled() {
                        return Ok(None);
                    }
                    v2::prepare_for_pow(
                        runtime,
                        origin.v2()?.origin(),
                        parent_terminal.as_ref(),
                        input,
                    )
                    .map_err(|e| e.to_string())?
                }};
            }
            // These are supported producer specializations, not release
            // parameters. The embedded bank supplies all actual class limits.
            let prepared = match config.pages() {
                63 => prepare!(63),
                206 => prepare!(206),
                207 => prepare!(207),
                209 => prepare!(209),
                210 => prepare!(210),
                211 => prepare!(211),
                223 => prepare!(223),
                255 => prepare!(255),
                _ => return Err("v2 bank uses an unsupported producer page specialization".into()),
            };
            if cancelled() {
                return Ok(None);
            }
            let built = prepared.seal_nonce(runtime, 0).map_err(|e| e.to_string())?;
            let uncancelled = std::sync::atomic::AtomicBool::new(false);
            let terminal =
                match v2::prove_built(runtime, &built, cancellation.unwrap_or(&uncancelled)) {
                    Ok(terminal) => terminal,
                    Err(noid_recursive::acceptance::history_step::v2::V2Error::Cancelled) => {
                        return Ok(None)
                    }
                    Err(error) => return Err(error.to_string()),
                };
            if cancelled() {
                return Ok(None);
            }
            if terminal.class() != class {
                return Err("v2 proof class drifted from the selected template".into());
            }
            let terminal_bytes =
                v2::encode_terminal(runtime, &terminal).map_err(|e| e.to_string())?;
            let retained_bytes = payload_weight
                .checked_add(terminal_bytes.len())
                .ok_or("prepared v2 retained-byte weight overflow")?;
            return Ok(Some(Self {
                block,
                terminal_bytes,
                end_accumulator,
                start_accumulator,
                parent_header: parent,
                expected_parent_id,
                expected_parent_height,
                payload_weight,
                retained_bytes,
                state_commit: prepared_state_commit,
                proof_class: MiningProofClass::V2(class),
            }));
        }
        if v2_class.is_some() || v21_class.is_some() || !object_openings.is_empty() {
            return Err("v2 template data before activation".into());
        }
        let runtime = runtime.legacy()?;
        let parent_terminal = match (parent.height, parent_history_step_terminal_bytes) {
            (0, None) => None,
            (0, Some(_)) => {
                return Err("genesis parent unexpectedly has a HistoryStep terminal".into());
            }
            (_, Some(bytes)) => Some(
                noid_recursive::acceptance::history_step::decode_history_step_terminal(
                    runtime, &bytes,
                )
                .map_err(|error| format!("parent HistoryStep terminal: {error}"))?,
            ),
            (_, None) => return Err("non-genesis parent HistoryStep terminal is missing".into()),
        };
        if cancelled() {
            return Ok(None);
        }

        let stream = noid_chain::validate_block_page_stream(&block.transactions)
            .map_err(|error| format!("prepared block body is non-canonical: {error}"))?;
        let proof_class = stream.proof_class;
        let witness = match proof_class {
            noid_chain::consensus::paged_spend::BlockProofClass::B25 => {
                noid_block::prepare_history_step_witness::<25>(
                    block,
                    context,
                    authorization_proofs,
                    ghost,
                    runtime,
                    parent_terminal.as_ref(),
                )
                .map(PreparedWitness::B25)
            }
            noid_chain::consensus::paged_spend::BlockProofClass::B255 => {
                noid_block::prepare_history_step_witness::<255>(
                    block,
                    context,
                    authorization_proofs,
                    ghost,
                    runtime,
                    parent_terminal.as_ref(),
                )
                .map(PreparedWitness::B255)
            }
        }
        .map_err(|error| error.to_string())?;
        if cancelled() {
            return Ok(None);
        }

        // The relation is nonce-free: finish the exact template (every native
        // check except PoW) and prove the complete HistoryStep before any
        // nonce search. Post-nonce work is one native PoW check + atomic
        // commit.
        macro_rules! finish_and_prove {
            ($witness:expr) => {{
                let (block, built, end) = $witness
                    .finish_template(runtime)
                    .map_err(|error| error.to_string())?;
                if cancelled() {
                    return Ok(None);
                }
                let terminal = match cancellation {
                    Some(cancellation) => {
                        match noid_recursive::acceptance::history_step::prove_built_history_step_terminal_cancellable(
                            runtime,
                            &built,
                            cancellation,
                        ) {
                            Ok(terminal) => terminal,
                            Err(noid_recursive::acceptance::history_step::HistoryStepError::Cancelled) => {
                                return Ok(None);
                            }
                            Err(error) => return Err(error.to_string()),
                        }
                    }
                    None => noid_recursive::acceptance::history_step::prove_built_history_step_terminal(
                        runtime,
                        &built,
                    )
                    .map_err(|error| error.to_string())?,
                };
                if cancelled() {
                    return Ok(None);
                }
                let terminal_bytes =
                    noid_recursive::acceptance::history_step::encode_history_step_terminal(
                        runtime, &terminal,
                    )
                    .map_err(|error| error.to_string())?;
                if cancelled() {
                    return Ok(None);
                }
                (block, terminal_bytes, end)
            }};
        }
        let (block, terminal_bytes, end_accumulator) = match witness {
            PreparedWitness::B25(witness) => finish_and_prove!(witness),
            PreparedWitness::B255(witness) => finish_and_prove!(witness),
        };

        let retained_bytes = payload_weight
            .checked_add(terminal_bytes.len())
            .ok_or_else(|| "prepared HistoryStep retained-byte weight overflow".to_string())?;

        Ok(Some(Self {
            block,
            terminal_bytes,
            end_accumulator,
            start_accumulator,
            parent_header: parent,
            expected_parent_id,
            expected_parent_height,
            payload_weight,
            retained_bytes,
            state_commit: prepared_state_commit,
            proof_class: MiningProofClass::Legacy(proof_class),
        }))
    }

    pub fn pow_header(&self, nonce: u128) -> noid_chain::BlockHeader {
        let mut header = self.block.header;
        header.nonce = nonce;
        header
    }

    pub fn user_page_count(&self) -> usize {
        noid_chain::block::native_assets::validate_scheduled_block_page_stream(
            &self.block.transactions,
            self.block.header.height,
        )
        .expect("prepared block has a canonical body")
        .page_count()
    }

    pub fn proof_class(&self) -> MiningProofClass {
        self.proof_class
    }

    pub const fn expected_parent_id(&self) -> [u8; 32] {
        self.expected_parent_id
    }

    pub const fn expected_parent_height(&self) -> u64 {
        self.expected_parent_height
    }

    /// Consensus-bounded serialized block and authorization payload weight.
    pub const fn payload_weight(&self) -> usize {
        self.payload_weight
    }

    /// Exact block/auth byte weight plus the staged builder's allocated
    /// witness buffer. External lifecycle admission uses this independently
    /// of the consensus payload cap.
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Seal the winning nonce with one native PoW check and create the only
    /// complete network/storage block object.
    ///
    /// The complete HistoryStep terminal was already proven at preparation:
    /// the relation is nonce-free and binds the semantic projection, so it
    /// covers every nonce of this exact template. `runtime` stays in the
    /// signature as the proving-authority witness of the caller's phase.
    pub fn prove(self, _runtime: &HistoryStepRuntime, nonce: u128) -> Result<ProvedBlock, String> {
        let sealed_header = self.pow_header(nonce);
        validate_pow(&sealed_header).map_err(|error| format!("proof of work: {error}"))?;
        let end = self
            .start_accumulator
            .advance(&self.parent_header, &sealed_header)
            .map_err(|error| format!("sealed accumulator transition failed: {error:?}"))?;
        if end != self.end_accumulator {
            return Err("sealed boundary drifted from the proven template".to_string());
        }
        let mut block = self.block;
        block.header.nonce = nonce;
        // SAFETY: legacy `finish_template` or v2 `prepare_candidate_input`
        // performed the complete native consensus checks for this exact
        // template, `validate_pow` above checked the
        // only nonce-dependent rule, and `terminal_bytes` is the canonical
        // encoding of the terminal returned directly by the pinned prover at
        // preparation. The local commit intentionally does not verify its own
        // freshly-authored proof a second time.
        let local_commit = unsafe {
            self.state_commit
                .seal_after_trusted_history_step_proof_unchecked(block, self.terminal_bytes)
        }?;
        Ok(ProvedBlock { local_commit })
    }
}

impl ProvedBlock {
    pub const fn block(&self) -> &Block {
        self.local_commit.block()
    }

    pub const fn bundle(&self) -> &noid_chain::AcceptedBlockBundle {
        self.local_commit.bundle()
    }

    /// Consume the post-prover capability and commit without replaying the
    /// proof that this process has just generated successfully.
    pub fn commit(self, chain: &mut MdbxChainContext) -> Result<CommittedBlock, MdbxContextError> {
        let (block, bundle) = chain.commit_locally_proved_next_block(self.local_commit)?;
        Ok(CommittedBlock { block, bundle })
    }
}

impl CommittedBlock {
    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn bundle(&self) -> &noid_chain::AcceptedBlockBundle {
        &self.bundle
    }

    pub fn into_parts(self) -> (Block, noid_chain::AcceptedBlockBundle) {
        (self.block, self.bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::params::GENESIS_TARGET;
    use noid_poseidon2b::primitives::Address;

    fn header(height: u64, prev_block_hash: [u8; 32]) -> noid_chain::BlockHeader {
        noid_chain::BlockHeader {
            prev_block_hash,
            state_root: [height as u8; 32],
            tx_root: [0x33; 32],
            timestamp: 1_000 + height,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: GENESIS_TARGET,
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height,
        }
    }

    #[test]
    fn production_boundary_uses_parent_anchor_before_advancing_child_anchor() {
        let genesis = noid_chain::consensus::genesis_header();
        let boundary = header(144, [0x11; 32]);
        let child = header(145, block_id(&boundary));

        let start = accumulator_from_header_boundary(&boundary, &genesis);
        start
            .validate_local_header_boundary(&boundary, &genesis)
            .expect("block 144 terminal still carries the genesis anchor");

        let end = start
            .advance(&boundary, &child)
            .expect("144 -> 145 advances the recursive boundary");
        end.validate_local_header_boundary(&child, &boundary)
            .expect("block 145 terminal carries the derived block-144 anchor");

        let conflated = accumulator_from_header_boundary(&boundary, &boundary);
        assert!(matches!(
            conflated.validate_local_header_boundary(&boundary, &boundary),
            Err(
                noid_recursive::ChainAccumulatorLocalBoundaryError::EpochAnchorHeight {
                    expected: 0,
                    actual: 144,
                }
            )
        ));
    }
}
