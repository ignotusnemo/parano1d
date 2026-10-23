// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Release-pinned two-class v2 artifacts. A metadata file or an adjacent hash
//! is never its own trust anchor. Each matrix has an independent load lock.

use noid_ivc_core::field_r1cs::{BuildAuthenticatedFieldR1csSeal, CompactFieldR1cs};
use noid_recursive::{
    acceptance::history_step::v2::{banked as v2, V2Error},
    HistoryStepMatrixLease,
};
use std::{
    io::Read,
    sync::{Arc, Mutex},
};

const MAGIC: &[u8; 8] = b"O1V2BNK1";
const PREFIX: usize = 8 + 2 * 32 + 4;
pub const V2_METADATA_FILE: &str = "v2-runtime-metadata.bin";
pub const V2_METADATA_MAX_BYTES: usize =
    PREFIX + noid_recursive::HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES;
pub const V2_MATRIX_MAX_BYTES: usize = 1024 * 1024 * 1024;

pub const fn v2_matrix_file_name(class: v2::Class) -> &'static str {
    match class {
        v2::Class::Small => "v2-small.field-r1cs.zst",
        v2::Class::Large => "v2-large.field-r1cs.zst",
    }
}

pub struct V2RuntimeMetadata {
    bank: v2::Bank,
    parts: v2::RuntimeParts,
}

impl V2RuntimeMetadata {
    pub fn bank(&self) -> &v2::Bank {
        &self.bank
    }

    pub fn parts(&self) -> &v2::RuntimeParts {
        &self.parts
    }

    /// Runtime files receive full semantic authentication on their first use.
    pub fn into_runtime(self, compressed: [Arc<[u8]>; 2]) -> Result<v2::Runtime, String> {
        for bytes in &compressed {
            check_compressed_length(bytes.len())?;
        }
        let sources = v2::Class::ALL.map(|class| CompressedMatrix {
            compressed: Arc::clone(&compressed[class.index()]),
            shape: self.bank.config().class(class).shape(),
            digest: self.bank.matrix_digest(class),
            build_seal: None,
            cache: Mutex::new(None),
        });
        v2::Runtime::new(self.bank, self.parts, Box::new(MatrixSources(sources)))
            .map_err(|e| e.to_string())
    }

    /// Authenticate all canonical rows during executable staging. The caller
    /// must embed the exact bytes checked here, not another file with the same
    /// name or an operator-supplied checksum.
    pub fn preflight_build_matrix(
        &self,
        class: v2::Class,
        compressed: &[u8],
    ) -> Result<BuildAuthenticatedFieldR1csSeal, String> {
        let canonical = decompress_matrix(compressed).map_err(|e| e.to_string())?;
        let canonical_bytes = canonical.len();
        let shape = self.bank.config().class(class).shape();
        let digest = self.bank.matrix_digest(class);
        CompactFieldR1cs::open(canonical.into_boxed_slice(), shape, digest)
            .map_err(|e| e.to_string())?;
        // SAFETY: the complete semantic scan above authenticated these exact
        // canonical bytes against the independently pinned bank and class.
        Ok(unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(shape, digest, canonical_bytes)
        })
    }

    /// Use immutable artifacts already authenticated by the executable build.
    /// File-based loaders must call `into_runtime` instead.
    ///
    /// # Safety
    /// Each compressed blob and seal must be the exact immutable pair emitted
    /// by a build that ran `preflight_build_matrix` for this bank and class.
    pub unsafe fn into_embedded_runtime(
        self,
        compressed: [&'static [u8]; 2],
        seals: [BuildAuthenticatedFieldR1csSeal; 2],
    ) -> Result<v2::Runtime, String> {
        for class in v2::Class::ALL {
            let seal = seals[class.index()];
            check_compressed_length(compressed[class.index()].len())?;
            if seal.shape() != self.bank.config().class(class).shape()
                || seal.statement_digest() != self.bank.matrix_digest(class)
                || seal.canonical_bytes() > V2_MATRIX_MAX_BYTES
            {
                return Err("v2 embedded matrix seal differs from its pinned class".into());
            }
        }
        let sources = v2::Class::ALL.map(|class| CompressedMatrix {
            compressed: Arc::from(compressed[class.index()]),
            shape: self.bank.config().class(class).shape(),
            digest: self.bank.matrix_digest(class),
            build_seal: Some(seals[class.index()]),
            cache: Mutex::new(None),
        });
        v2::Runtime::new(self.bank, self.parts, Box::new(MatrixSources(sources)))
            .map_err(|e| e.to_string())
    }
}

pub fn encode_v2_runtime_metadata(
    bank: &v2::Bank,
    parts: &v2::RuntimeParts,
) -> Result<Vec<u8>, String> {
    let digests = v2::Class::ALL.map(|class| bank.matrix_digest(class));
    if v2::Bank::pin(digests, parts).digest() != bank.digest() {
        return Err("v2 bank and runtime recipe differ".into());
    }
    let parts = parts.encode_compact().map_err(|e| e.to_string())?;
    let mut bytes = Vec::with_capacity(PREFIX + parts.len());
    bytes.extend_from_slice(MAGIC);
    for digest in digests {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&parts);
    Ok(bytes)
}

pub fn decode_v2_runtime_metadata_pinned(
    bytes: &[u8],
    release_bank: [u8; 32],
) -> Result<V2RuntimeMetadata, String> {
    if bytes.len() <= PREFIX || bytes.len() > V2_METADATA_MAX_BYTES || !bytes.starts_with(MAGIC) {
        return Err("v2 runtime metadata framing".into());
    }
    let length = u32::from_le_bytes(bytes[PREFIX - 4..PREFIX].try_into().unwrap()) as usize;
    if length != bytes.len() - PREFIX {
        return Err("v2 runtime metadata length".into());
    }
    let parts = v2::RuntimeParts::decode_compact(&bytes[PREFIX..]).map_err(|e| e.to_string())?;
    let digests = [
        bytes[8..40].try_into().unwrap(),
        bytes[40..72].try_into().unwrap(),
    ];
    let bank = v2::Bank::pin(digests, &parts);
    if bank.digest() != release_bank {
        return Err("v2 runtime differs from the independently supplied bank pin".into());
    }
    Ok(V2RuntimeMetadata { bank, parts })
}

struct MatrixSources([CompressedMatrix; 2]);
struct CompressedMatrix {
    compressed: Arc<[u8]>,
    shape: noid_ivc_core::proof::FieldShape,
    digest: [u8; 32],
    build_seal: Option<BuildAuthenticatedFieldR1csSeal>,
    cache: Mutex<Option<Arc<CompactFieldR1cs>>>,
}

fn check_compressed_length(length: usize) -> Result<(), String> {
    if length == 0 || length > V2_MATRIX_MAX_BYTES {
        Err("v2 compressed matrix bound".into())
    } else {
        Ok(())
    }
}

fn decompress_matrix(compressed: &[u8]) -> Result<Vec<u8>, V2Error> {
    check_compressed_length(compressed.len()).map_err(|_| V2Error::Matrix)?;
    let mut decoder = zstd::stream::read::Decoder::new(compressed).map_err(|_| V2Error::Matrix)?;
    decoder.window_log_max(27).map_err(|_| V2Error::Matrix)?;
    let mut canonical = Vec::new();
    decoder
        .take(V2_MATRIX_MAX_BYTES as u64 + 1)
        .read_to_end(&mut canonical)
        .map_err(|_| V2Error::Matrix)?;
    if canonical.len() > V2_MATRIX_MAX_BYTES {
        return Err(V2Error::Matrix);
    }
    Ok(canonical)
}

impl v2::MatrixSource for MatrixSources {
    fn release_cached_matrices(&self) {
        for source in &self.0 {
            let cached = source.cache.lock().ok().and_then(|mut cache| cache.take());
            drop(cached);
        }
    }

    fn load(&self, class: v2::Class) -> Result<HistoryStepMatrixLease, V2Error> {
        let source = &self.0[class.index()];
        // The other class has a separate mutex. Loading a cold large matrix
        // cannot hold the lock of an already available small matrix.
        let mut cache = source.cache.lock().map_err(|_| V2Error::Matrix)?;
        if cache.is_none() {
            let canonical = decompress_matrix(&source.compressed)?.into_boxed_slice();
            let matrix = match source.build_seal {
                // SAFETY: only the unsafe embedded-pair constructor installs
                // a seal, and these owned bytes have no mutable outside alias.
                Some(seal) => unsafe {
                    CompactFieldR1cs::open_build_authenticated(canonical, seal)
                },
                None => CompactFieldR1cs::open(canonical, source.shape, source.digest),
            }
            .and_then(CompactFieldR1cs::into_startup_packed)
            .map_err(|_| V2Error::Matrix)?;
            *cache = Some(Arc::new(matrix));
        }
        Ok(HistoryStepMatrixLease::Compact(Arc::clone(
            cache.as_ref().unwrap(),
        )))
    }
}
