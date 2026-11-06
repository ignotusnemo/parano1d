// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Storage for immutable embedded artifacts and bounded metadata inflation.

use std::{io::Read, ops::Deref, sync::Arc};

#[derive(Clone)]
pub(crate) enum ArtifactBytes {
    Embedded(&'static [u8]),
    Owned(Arc<[u8]>),
}

impl Deref for ArtifactBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Embedded(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

/// Inflate one build-produced frame before the ordinary release-pinned decode.
/// The expected length comes from the executable, independently of the frame.
pub fn decode_embedded_metadata(
    compressed: &[u8],
    expected_bytes: usize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, String> {
    if expected_bytes == 0
        || expected_bytes > maximum_bytes
        || compressed.is_empty()
        || compressed.len() > maximum_bytes
    {
        return Err("embedded metadata size bound".into());
    }
    let mut decoder = zstd::stream::read::Decoder::with_buffer(compressed)
        .map_err(|e| e.to_string())?
        .single_frame();
    decoder.window_log_max(27).map_err(|e| e.to_string())?;
    let mut bytes = Vec::with_capacity(expected_bytes);
    (&mut decoder)
        .take(expected_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() != expected_bytes || !decoder.finish().is_empty() {
        return Err("embedded metadata length or trailing data".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_storage_borrows_the_original_bytes() {
        static BYTES: &[u8] = &[1, 2, 3, 4];
        let borrowed = ArtifactBytes::Embedded(BYTES);
        assert_eq!(borrowed.as_ptr(), BYTES.as_ptr());
        let bytes: Arc<[u8]> = Arc::from(BYTES);
        let owned = ArtifactBytes::Owned(Arc::clone(&bytes));
        assert_eq!(owned.as_ptr(), bytes.as_ptr());
    }

    #[test]
    fn metadata_inflation_rejects_wrong_lengths_trailing_frames_and_truncation() {
        let bytes = vec![17; 4096];
        let encoded = zstd::bulk::compress(&bytes, 3).unwrap();
        assert_eq!(
            decode_embedded_metadata(&encoded, bytes.len(), 8192).unwrap(),
            bytes
        );
        for length in [0, 4095, 4097, 8193] {
            assert!(decode_embedded_metadata(&encoded, length, 8192).is_err());
        }
        for length in [0, 1, encoded.len() - 1] {
            assert!(decode_embedded_metadata(&encoded[..length], 4096, 8192).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_embedded_metadata(&trailing, 4096, 8192).is_err());
        trailing = [encoded.as_slice(), encoded.as_slice()].concat();
        assert!(decode_embedded_metadata(&trailing, 4096, 8192).is_err());
    }
}
