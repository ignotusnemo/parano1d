// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Preflight-authenticated embedded `HistoryStep` release pack.
//!
//! Development builds may contain no pack. Transitional builds include the
//! pinned old runtime metadata and both canonical matrices. `retired-history`
//! omits those matrices and keeps independently pinned preprocessing keys.
//! The legacy pack retains its existing explicit release preflight. New v2
//! matrices are authenticated in `build.rs` before it emits private seals.
//! Old rows, when included, may retain their derived layout in the local cache.

use noid_miner::{
    EmbeddedHistoryStepMatrixError, EmbeddedHistoryStepMatrixLeaf, EmbeddedHistoryStepMatrixSource,
    HISTORY_STEP_PACK_LEAF_COUNT,
};

pub struct EmbeddedHistoryStepPack {
    runtime_metadata: &'static [u8],
    runtime_metadata_bytes: usize,
    runtime_metadata_digest: [u8; 32],
    leaves: Option<[EmbeddedHistoryStepMatrixLeaf; HISTORY_STEP_PACK_LEAF_COUNT]>,
}

impl EmbeddedHistoryStepPack {
    pub fn runtime_metadata(&self) -> Result<Vec<u8>, String> {
        noid_miner::decode_embedded_metadata(
            self.runtime_metadata,
            self.runtime_metadata_bytes,
            noid_miner::HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
        )
    }

    pub const fn runtime_metadata_digest(&self) -> [u8; 32] {
        self.runtime_metadata_digest
    }

    pub const fn has_legacy_matrices(&self) -> bool {
        self.leaves.is_some()
    }

    pub fn matrix_source(
        &self,
        runtime_cache_directory: Option<std::path::PathBuf>,
    ) -> Result<Box<dyn noid_recursive::HistoryStepMatrixSource>, EmbeddedHistoryStepMatrixError>
    {
        let Some(leaves) = self.leaves else {
            return Ok(Box::new(RetiredLegacyRows));
        };
        // SAFETY: this private pack is emitted only from the canonical pack
        // accepted by the explicit release preflight.
        let source = unsafe { EmbeddedHistoryStepMatrixSource::from_release_build(leaves) }?;
        Ok(Box::new(match runtime_cache_directory {
            Some(directory) => source.with_runtime_cache(directory),
            None => source,
        }))
    }

    pub fn embedded_bytes_total(&self) -> usize {
        self.runtime_metadata.len()
            + self
                .leaves
                .iter()
                .flatten()
                .map(|leaf| leaf.compressed_canonical().len())
                .sum::<usize>()
    }
}

struct RetiredLegacyRows;
impl noid_recursive::HistoryStepMatrixSource for RetiredLegacyRows {
    fn load(
        &self,
        _: noid_recursive::CanonicalHistoryStepClassId,
    ) -> Result<noid_recursive::HistoryStepMatrixLease, noid_recursive::HistoryStepMatrixSourceError>
    {
        Err(noid_recursive::HistoryStepMatrixSourceError)
    }
}

struct EmbeddedRetirementKeys {
    encoded: [&'static [u8]; 2],
    release_pins: [[u8; 32]; 2],
}

pub fn embedded_retirement_keys(
    bank: &noid_recursive::acceptance::history_step_bank::PinnedHistoryStepClassBank,
) -> Result<
    Option<noid_recursive::acceptance::history_step::v2::banked::PinnedRetirementKeys>,
    String,
> {
    GENERATED_RETIREMENT_KEYS
        .as_ref()
        .map(|keys| {
            noid_recursive::acceptance::history_step::v2::banked::PinnedRetirementKeys::from_release(
                bank,
                keys.encoded,
                keys.release_pins,
            )
            .map_err(|e| e.to_string())
        })
        .transpose()
}

include!(concat!(env!("OUT_DIR"), "/retirement_keys.rs"));
include!(concat!(env!("OUT_DIR"), "/v2_retirement_keys.rs"));
include!(concat!(env!("OUT_DIR"), "/unified_origin.rs"));

pub fn embedded_v2_retirement_keys(
    bank: &noid_recursive::acceptance::history_step::v2::banked::Bank,
) -> Result<
    Option<noid_recursive::acceptance::history_step::v2::banked::PinnedRetirementKeys>,
    String,
> {
    GENERATED_V2_RETIREMENT_KEYS.as_ref().map(|keys| {
        noid_recursive::acceptance::history_step::v2::banked::PinnedRetirementKeys::from_banked_release(
            bank, keys.encoded, keys.release_pins,
        ).map_err(|e| e.to_string())
    }).transpose()
}

#[cfg(feature = "retired-v2-history")]
pub fn embedded_retirement_origin() -> Option<&'static [u8]> {
    GENERATED_UNIFIED_ORIGIN
}

/// Carry the selected mainnet ancestry proof with matrix-free executables.
/// Admission still verifies it through the ordinary pinned-key proof path.
#[cfg(all(
    feature = "retired-history",
    not(feature = "retired-v2-history"),
    not(feature = "isolated-v1-1-testnet")
))]
pub fn embedded_retirement_origin() -> Option<&'static [u8]> {
    Some(include_bytes!("../assets/mainnet-retirement.origin"))
}

#[cfg(all(
    not(feature = "retired-v2-history"),
    not(all(feature = "retired-history", not(feature = "isolated-v1-1-testnet")))
))]
pub fn embedded_retirement_origin() -> Option<&'static [u8]> {
    None
}

/// `None` is possible only in a pack-free development build.  `build.rs`
/// rejects a release build without its required pinned artifacts.
pub fn embedded_history_step_pack() -> Option<&'static EmbeddedHistoryStepPack> {
    GENERATED_HISTORY_STEP_PACK.as_ref()
}

include!(concat!(env!("OUT_DIR"), "/history_step_pack.rs"));

struct EmbeddedV2Pack {
    metadata: &'static [u8],
    metadata_bytes: usize,
    compressed_matrices: Option<[&'static [u8]; 2]>,
    release_bank: [u8; 32],
    build_seals: Option<[noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal; 2]>,
}

pub fn embedded_v2_runtime() -> Result<
    Option<std::sync::Arc<noid_recursive::acceptance::history_step::v2::banked::Runtime>>,
    String,
> {
    embedded_v2_pack_runtime(GENERATED_V2_PACK.as_ref())
}

pub fn embedded_authorization_runtime() -> Result<
    Option<std::sync::Arc<noid_recursive::acceptance::history_step::v2::banked::Runtime>>,
    String,
> {
    embedded_v2_pack_runtime(GENERATED_AUTHORIZATION_PACK.as_ref())
}

fn embedded_v2_pack_runtime(
    pack: Option<&EmbeddedV2Pack>,
) -> Result<
    Option<std::sync::Arc<noid_recursive::acceptance::history_step::v2::banked::Runtime>>,
    String,
> {
    let Some(pack) = pack else {
        return Ok(None);
    };
    let metadata = noid_miner::v2_artifacts::decode_v2_runtime_metadata_pinned(
        &noid_miner::decode_embedded_metadata(
            pack.metadata,
            pack.metadata_bytes,
            noid_miner::v2_artifacts::V2_METADATA_MAX_BYTES,
        )?,
        pack.release_bank,
    )?;
    // SAFETY: embed_v2_pack runs the full semantic authentication before
    // staging these exact immutable bytes and emitting this private seal.
    let runtime = match (pack.compressed_matrices, pack.build_seals) {
        (Some(matrices), Some(seals)) => unsafe { metadata.into_embedded_runtime(matrices, seals) },
        (None, None) => metadata.into_metadata_only_runtime(),
        _ => return Err("embedded ancestry matrix/seal pairing".into()),
    }?;
    Ok(Some(std::sync::Arc::new(runtime)))
}

include!(concat!(env!("OUT_DIR"), "/v2_pack.rs"));
include!(concat!(env!("OUT_DIR"), "/authorization_pack.rs"));

struct EmbeddedV21Pack {
    metadata: &'static [u8],
    metadata_bytes: usize,
    compressed_matrices: [&'static [u8]; 3],
    release_bank: [u8; 32],
    build_seals: [noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal; 3],
}

pub fn embedded_finance_runtime() -> Result<
    Option<std::sync::Arc<noid_recursive::acceptance::history_step::v2::capacity_banked::Runtime>>,
    String,
> {
    let Some(pack) = GENERATED_V21_PACK.as_ref() else {
        return Ok(None);
    };
    let metadata = noid_miner::v21_artifacts::decode_v21_runtime_metadata_pinned(
        &noid_miner::decode_embedded_metadata(
            pack.metadata,
            pack.metadata_bytes,
            noid_miner::v21_artifacts::V21_METADATA_MAX_BYTES,
        )?,
        pack.release_bank,
    )?;
    // SAFETY: embed_v21_pack fully authenticates each class before staging
    // these exact immutable bytes and emitting the corresponding private seal.
    unsafe { metadata.into_embedded_runtime(pack.compressed_matrices, pack.build_seals) }
        .map(|runtime| Some(std::sync::Arc::new(runtime)))
}

include!(concat!(env!("OUT_DIR"), "/v21_pack.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use noid_recursive::acceptance::history_step_bank::CanonicalHistoryStepClassId;

    #[test]
    fn unified_origin_supports_its_first_child_without_historical_rows() {
        if !cfg!(feature = "retired-v2-history") {
            return;
        }
        let bytes = embedded_retirement_origin().unwrap();
        let certificate = noid_recursive::acceptance::history_step::v2::capacity_banked::UnifiedOriginCertificate::from_bytes(bytes).unwrap();
        let auth = certificate.authorization().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let runtime = crate::embedded_history_step_runtime(directory.path(), false)
            .unwrap()
            .unwrap();
        let checked = runtime.install_embedded_origin_bytes(bytes).unwrap();
        let parent = runtime
            .origin_for_parent(
                auth.parent_header(),
                auth.epoch_header(),
                auth.terminal_bytes(),
            )
            .unwrap();
        assert_eq!(parent.origin(), checked.origin());
        for class in noid_recursive::acceptance::history_step::v2::banked::Class::ALL {
            assert!(runtime.prepare_v2_matrix_cache(class).is_err());
        }
        let carrier =
            noid_chain::fork_origin_carrier::UnifiedOriginCarrier::from_bytes(bytes).unwrap();
        let old = runtime
            .origin_bytes(carrier.predecessor_request())
            .unwrap()
            .unwrap();
        assert_eq!(old, carrier.predecessor_bytes());
        let files = directory.path().join("fork-origins");
        let selected = files.join(format!(
            "{}.origin",
            hex::encode(checked.origin().request_binding())
        ));
        let previous = files.join(format!(
            "{}.origin",
            hex::encode(carrier.predecessor_request())
        ));
        assert_eq!(std::fs::read(&selected).unwrap().as_slice(), bytes);
        assert_eq!(
            std::fs::read(&previous).unwrap().as_slice(),
            carrier.predecessor_bytes()
        );
        // Normalize a predecessor file from the earlier combined-cache layout.
        std::fs::write(&previous, bytes).unwrap();
        runtime.retain_origin(&checked).unwrap();
        assert_eq!(std::fs::read(&selected).unwrap().as_slice(), bytes);
        assert_eq!(
            std::fs::read(&previous).unwrap().as_slice(),
            carrier.predecessor_bytes()
        );
        std::fs::remove_file(&previous).unwrap();
        runtime.retain_origin(&checked).unwrap();
        assert_eq!(
            std::fs::read(&previous).unwrap().as_slice(),
            carrier.predecessor_bytes()
        );
    }

    #[test]
    fn unified_origin_rejects_substituted_claims_proofs_and_routing() {
        use noid_chain::fork_origin_carrier::UnifiedOriginCarrier;
        if !cfg!(feature = "retired-v2-history") {
            return;
        }
        let carrier =
            UnifiedOriginCarrier::from_bytes(embedded_retirement_origin().unwrap()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let runtime = crate::embedded_history_step_runtime(directory.path(), false)
            .unwrap()
            .unwrap();
        let evaluations: Vec<_> = carrier
            .evaluations()
            .map(|(c, p)| (c, p.to_vec()))
            .collect();
        let mut routing = carrier.request_binding();
        routing[0] ^= 1;
        let wrong_routing = UnifiedOriginCarrier::new(
            routing,
            carrier.authorization_bytes(),
            carrier.reduction_bytes(),
            &evaluations,
        )
        .unwrap();
        let mut wrong_class = evaluations.clone();
        assert_eq!(wrong_class.len(), 1);
        wrong_class[0].0 ^= 1;
        let wrong_class = UnifiedOriginCarrier::new(
            carrier.request_binding(),
            carrier.authorization_bytes(),
            carrier.reduction_bytes(),
            &wrong_class,
        )
        .unwrap();
        let mut damaged = evaluations.clone();
        *damaged[0].1.last_mut().unwrap() ^= 1;
        let damaged = UnifiedOriginCarrier::new(
            carrier.request_binding(),
            carrier.authorization_bytes(),
            carrier.reduction_bytes(),
            &damaged,
        )
        .unwrap();
        let mut reduction = carrier.reduction_bytes().to_vec();
        *reduction.last_mut().unwrap() ^= 1;
        let wrong_fold = UnifiedOriginCarrier::new(
            carrier.request_binding(),
            carrier.authorization_bytes(),
            &reduction,
            &evaluations,
        )
        .unwrap();
        for invalid in [wrong_routing, wrong_class, damaged, wrong_fold] {
            assert!(runtime
                .install_origin_bytes(&invalid.to_bytes().unwrap())
                .is_err());
        }
        assert!(runtime
            .install_origin_bytes(embedded_retirement_origin().unwrap())
            .is_ok());
    }

    #[test]
    #[ignore = "requires NOID_RETIREMENT_CHAIN_FIXTURE containing a closed, synchronized chain copy"]
    fn retired_ancestry_prepares_and_verifies_current_classes() {
        use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
        use noid_miner::{
            template::{TemplateBuilder, TemplateChainSnapshot},
            PreparedBlockAttempt,
        };
        use noid_recursive::acceptance::history_step::v2::capacity_banked as v21;
        assert!(cfg!(feature = "retired-v2-history"));
        noid_miner::configure_process_cpu_budget_with_threads(
            noid_miner::ProcessCpuBudgetMode::ProofOnly,
            Some(8),
        )
        .unwrap();
        let fixture = std::path::PathBuf::from(
            std::env::var_os("NOID_RETIREMENT_CHAIN_FIXTURE").expect("closed chain fixture"),
        );
        let directory = tempfile::tempdir().unwrap();
        let runtime = crate::embedded_history_step_runtime(directory.path(), true)
            .unwrap()
            .unwrap();
        let bytes = embedded_retirement_origin().unwrap();
        noid_miner::install_inbound_verifier_cpu(|| runtime.install_embedded_origin_bytes(bytes))
            .unwrap()
            .unwrap();
        for class in noid_recursive::acceptance::history_step::v2::banked::Class::ALL {
            assert!(runtime.prepare_v2_matrix_cache(class).is_err());
        }
        let mut chain = noid_chain::storage::MdbxChainContext::open_or_create(&fixture).unwrap();
        let original_tip = (chain.tip_height(), chain.tip_hash());
        assert!(noid_chain::consensus::params::v2_1_active(original_tip.0));
        let ghost = crate::prepare_history_step_ghost_authorization().unwrap();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for class in v21::Class::ALL {
            let snapshot = TemplateChainSnapshot::from_context(&mut chain).unwrap();
            let epoch = snapshot.child_tx_epoch_anchor_header;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .max(snapshot.parent.timestamp + 1);
            let pool = AsyncMempool::new(ChainView::from_mdbx(&chain), MempoolConfig::default());
            let mut template = executor
                .block_on(
                    TemplateBuilder::new(pool)
                        .with_history_protocol(&runtime)
                        .build_from_snapshot(
                            snapshot,
                            noid_poseidon2b::primitives::Address([7; 32]),
                            now,
                        ),
                )
                .expect("current-bank template");
            template.v21_class = Some(class);
            let started = std::time::Instant::now();
            let prepared = noid_miner::install_history_step_phase_cpu(|| {
                PreparedBlockAttempt::prepare(template, &runtime, &ghost, now)
            })
            .unwrap()
            .unwrap();
            let prove_ms = started.elapsed().as_millis();
            let header = prepared.pow_header(0);
            let current = runtime.finance_at(header.height).unwrap();
            let terminal = v21::decode_terminal(current, prepared.terminal_bytes()).unwrap();
            assert_eq!(terminal.class(), class);
            let wanted = terminal.claimed_origin(current).unwrap().into();
            let origin = runtime.verified_origin(&wanted).unwrap();
            let verify = std::time::Instant::now();
            let checked = noid_miner::install_inbound_verifier_cpu(|| {
                v21::verify_terminal(current, origin.v21().unwrap(), &terminal, &header, &epoch)
            })
            .unwrap()
            .unwrap();
            assert_eq!(checked.accumulator().height, original_tip.0 + 1);
            assert_eq!((chain.tip_height(), chain.tip_hash()), original_tip);
            println!(
                "{}",
                serde_json::json!({"class":class.wire_id(),"prepare_ms":prove_ms,"verify_ms":verify.elapsed().as_millis(),"terminal_bytes":prepared.terminal_bytes().len(),"historical_rows_available":false})
            );
        }
    }

    #[test]
    fn generated_v2_pack_authenticates_both_classes_and_matches_the_profile() {
        let Some(runtime) = embedded_v2_runtime().unwrap() else {
            return; // Pack-free development build.
        };
        assert_eq!(
            runtime.bank().config().schedule(),
            noid_chain::consensus::forks::ACTIVE_SCHEDULE
        );
        for class in noid_recursive::acceptance::history_step::v2::banked::Class::ALL {
            if cfg!(feature = "retired-v2-history") {
                assert!(runtime.prepare_matrix_cache(class).is_err());
            } else {
                runtime
                    .prepare_matrix_cache(class)
                    .expect("embedded class matrix");
            }
        }
    }

    #[test]
    fn retired_build_cannot_load_either_legacy_class() {
        if !cfg!(feature = "retired-history") {
            return;
        }
        let pack = embedded_history_step_pack().expect("retired build requires legacy metadata");
        assert!(!pack.has_legacy_matrices());
        let source = pack.matrix_source(None).unwrap();
        for index in 0..HISTORY_STEP_PACK_LEAF_COUNT {
            assert!(source
                .load(CanonicalHistoryStepClassId::from_index(index).unwrap())
                .is_err());
        }
        let metadata = noid_miner::decode_history_step_runtime_metadata_pinned(
            &pack.runtime_metadata().unwrap(),
            pack.runtime_metadata_digest(),
        )
        .unwrap();
        assert!(embedded_retirement_keys(metadata.bank()).unwrap().is_some());
    }

    #[test]
    fn embedded_retirement_origin_verifies_without_old_rows_and_rejects_corruption() {
        let Some(bytes) = embedded_retirement_origin() else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let runtime = crate::embedded_history_step_runtime(directory.path(), false)
            .unwrap()
            .unwrap();
        let mut damaged = bytes.to_vec();
        let middle = damaged.len() / 2;
        damaged[middle] ^= 1;
        assert!(runtime.install_origin_bytes(&damaged).is_err());
        assert!(!directory.path().join("fork-origins").exists());

        let checked = runtime.install_origin_bytes(bytes).unwrap();
        assert_eq!(
            checked.origin().activation_height().unwrap(),
            if cfg!(feature = "retired-v2-history") {
                noid_chain::consensus::params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT.unwrap()
            } else {
                noid_chain::consensus::params::MAINNET_V2_ACTIVATION_HEIGHT
            }
        );
        runtime.retain_origin(&checked).unwrap();
        assert_eq!(
            runtime
                .origin_bytes(checked.origin().request_binding())
                .unwrap()
                .unwrap(),
            bytes
        );
        for index in 0..HISTORY_STEP_PACK_LEAF_COUNT {
            assert!(runtime
                .prepare_matrix_cache(CanonicalHistoryStepClassId::from_index(index).unwrap())
                .is_err());
        }
    }

    #[test]
    fn generated_pack_preserves_dense_class_order() {
        let Some(pack) = embedded_history_step_pack() else {
            return;
        };
        assert!(!pack.runtime_metadata().unwrap().is_empty());
        for (index, leaf) in pack.leaves.iter().flatten().enumerate() {
            assert_eq!(
                leaf.class(),
                CanonicalHistoryStepClassId::from_index(index).unwrap()
            );
            assert!(!leaf.compressed_canonical().is_empty());
            assert!(leaf.build_seal().canonical_bytes() > 0);
            assert_ne!(leaf.build_seal().statement_digest(), [0; 32]);
        }
        if cfg!(feature = "retired-history") {
            assert!(pack.leaves.is_none());
            assert!(GENERATED_RETIREMENT_KEYS.is_some());
        }
    }
}
