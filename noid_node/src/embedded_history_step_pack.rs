// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Build-authenticated embedded `HistoryStep` release pack.
//!
//! Development builds may contain no pack.  Official release builds contain
//! one pinned runtime-metadata artifact and the two canonical class
//! matrices, all authenticated by `build.rs` before rustc embeds them. The
//! packed runtime layout is derived once per release into the node's local
//! runtime cache directory.

use noid_miner::{
    EmbeddedHistoryStepMatrixError, EmbeddedHistoryStepMatrixLeaf, EmbeddedHistoryStepMatrixSource,
    HISTORY_STEP_PACK_LEAF_COUNT,
};

pub struct EmbeddedHistoryStepPack {
    runtime_metadata: &'static [u8],
    runtime_metadata_digest: [u8; 32],
    leaves: [EmbeddedHistoryStepMatrixLeaf; HISTORY_STEP_PACK_LEAF_COUNT],
}

impl EmbeddedHistoryStepPack {
    pub const fn runtime_metadata(&self) -> &'static [u8] {
        self.runtime_metadata
    }

    pub const fn runtime_metadata_digest(&self) -> [u8; 32] {
        self.runtime_metadata_digest
    }

    pub fn matrix_source(
        &self,
        runtime_cache_directory: Option<std::path::PathBuf>,
    ) -> Result<EmbeddedHistoryStepMatrixSource, EmbeddedHistoryStepMatrixError> {
        // SAFETY: this private pack is emitted only by `noid_node/build.rs`,
        // which authenticates every pinned canonical leaf.
        let source = unsafe { EmbeddedHistoryStepMatrixSource::from_release_build(self.leaves) }?;
        Ok(match runtime_cache_directory {
            Some(directory) => source.with_runtime_cache(directory),
            None => source,
        })
    }

    pub fn embedded_bytes_total(&self) -> usize {
        self.runtime_metadata.len()
            + self
                .leaves
                .iter()
                .map(|leaf| leaf.compressed_canonical().len())
                .sum::<usize>()
    }
}

/// `None` is possible only in a pack-free development build.  `build.rs`
/// rejects a release build without the complete pinned pack.
pub fn embedded_history_step_pack() -> Option<&'static EmbeddedHistoryStepPack> {
    GENERATED_HISTORY_STEP_PACK.as_ref()
}

include!(concat!(env!("OUT_DIR"), "/history_step_pack.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use noid_recursive::acceptance::history_step_bank::CanonicalHistoryStepClassId;

    #[test]
    fn generated_pack_preserves_dense_class_order() {
        let Some(pack) = embedded_history_step_pack() else {
            return;
        };
        assert!(!pack.runtime_metadata().is_empty());
        for (index, leaf) in pack.leaves.iter().enumerate() {
            assert_eq!(
                leaf.class(),
                CanonicalHistoryStepClassId::from_index(index).unwrap()
            );
            assert!(!leaf.compressed_canonical().is_empty());
            assert!(leaf.build_seal().canonical_bytes() > 0);
            assert!(leaf.build_seal().canonical_bytes() > 0);
        }
    }
}
