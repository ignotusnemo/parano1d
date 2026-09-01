// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use iced::widget::image::Handle as ImageHandle;
use zeroize::Zeroize;

use crate::model::SensitiveString;

const MAX_SECRET_PHOTO_BYTES: u64 = 256 << 20;
const MIN_SECRET_PHOTO_DIMENSION: u32 = 32;
const MIN_SECRET_PHOTO_DISTINCT_PIXELS: usize = 64;
const IMAGE_SECRET_CONTEXT: &str = "ParanO(1)d master secret from canonical image pixels v1";
const KEY_ID_CONTEXT: &str = "ParanO(1)d master secret fingerprint v1";

#[derive(Clone)]
pub struct PreparedPhoto {
    pub name: String,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub key_id: String,
    pub preview: ImageHandle,
    master_secret: SensitiveString,
}

impl std::fmt::Debug for PreparedPhoto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedPhoto")
            .field("name", &self.name)
            .field("size", &self.size)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("key_id", &self.key_id)
            .field("master_secret", &"<redacted>")
            .finish()
    }
}

impl PreparedPhoto {
    pub fn master_secret(&self) -> SensitiveString {
        self.master_secret.clone()
    }
}

pub fn prepare_secret_photo(path: PathBuf) -> Result<PreparedPhoto, String> {
    let metadata =
        std::fs::metadata(&path).map_err(|error| format!("Read {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err("Choose a photo.".into());
    }
    if metadata.len() == 0 {
        return Err("The selected photo is empty.".into());
    }
    if metadata.len() > MAX_SECRET_PHOTO_BYTES {
        return Err("The selected photo is larger than 256 MiB.".into());
    }

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());

    let (mut secret, width, height, preview) = decode_image_secret(&path).map_err(|error| {
        format!("Unsupported or unsafe photo. Use a private JPEG, PNG, WebP, GIF, BMP, or TIFF: {error}")
    })?;
    let key_id = key_id(&secret);
    let master_secret = SensitiveString::new(hex::encode(secret));
    secret.zeroize();
    Ok(PreparedPhoto {
        preview,
        name,
        size: metadata.len(),
        width,
        height,
        key_id,
        master_secret,
    })
}

fn decode_image_secret(path: &Path) -> Result<([u8; 32], u32, u32, ImageHandle), String> {
    let decoded = image::ImageReader::open(path)
        .map_err(|error| error.to_string())?
        .with_guessed_format()
        .map_err(|error| error.to_string())?
        .decode()
        .map_err(|error| error.to_string())?;
    let width = decoded.width();
    let height = decoded.height();
    let mut rgba = decoded.to_rgba8();
    validate_image_secret_source(width, height, rgba.as_raw())?;
    let secret = derive_image_secret(width, height, rgba.as_raw());
    let (preview_width, preview_height) = preview_dimensions(width, height);
    let preview_pixels = if preview_width == width && preview_height == height {
        rgba.into_raw()
    } else {
        let preview =
            image::imageops::thumbnail(&rgba, preview_width.max(1), preview_height.max(1));
        rgba.as_mut().zeroize();
        preview.into_raw()
    };
    let preview = ImageHandle::from_rgba(preview_width, preview_height, preview_pixels);
    Ok((secret, width, height, preview))
}

fn validate_image_secret_source(width: u32, height: u32, rgba: &[u8]) -> Result<(), String> {
    if width < MIN_SECRET_PHOTO_DIMENSION || height < MIN_SECRET_PHOTO_DIMENSION {
        return Err(format!(
            "the image must be at least {MIN_SECRET_PHOTO_DIMENSION} × {MIN_SECRET_PHOTO_DIMENSION} pixels"
        ));
    }

    let mut distinct = HashSet::with_capacity(MIN_SECRET_PHOTO_DISTINCT_PIXELS);
    for pixel in rgba.chunks_exact(4) {
        distinct.insert([pixel[0], pixel[1], pixel[2], pixel[3]]);
        if distinct.len() >= MIN_SECRET_PHOTO_DISTINCT_PIXELS {
            return Ok(());
        }
    }
    Err(format!(
        "the image must contain at least {MIN_SECRET_PHOTO_DISTINCT_PIXELS} distinct pixel values"
    ))
}

fn preview_dimensions(width: u32, height: u32) -> (u32, u32) {
    const MAX_PREVIEW_WIDTH: f64 = 1_000.0;
    const MAX_PREVIEW_HEIGHT: f64 = 560.0;
    let scale = (MAX_PREVIEW_WIDTH / f64::from(width.max(1)))
        .min(MAX_PREVIEW_HEIGHT / f64::from(height.max(1)))
        .min(1.0);
    (
        (f64::from(width) * scale).round().max(1.0) as u32,
        (f64::from(height) * scale).round().max(1.0) as u32,
    )
}

fn derive_image_secret(width: u32, height: u32, rgba: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(IMAGE_SECRET_CONTEXT);
    hasher.update(b"RGBA8");
    hasher.update(&width.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(&(rgba.len() as u64).to_le_bytes());
    hasher.update(rgba);
    *hasher.finalize().as_bytes()
}

fn key_id(secret: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ID_CONTEXT);
    hasher.update(secret);
    let digest = hasher.finalize();
    let encoded = hex::encode(&digest.as_bytes()[..8]);
    format!(
        "{}·{}·{}·{}",
        &encoded[..4],
        &encoded[4..8],
        &encoded[8..12],
        &encoded[12..]
    )
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use image::codecs::jpeg::JpegEncoder;
    use image::codecs::png::PngEncoder;
    use image::{ExtendedColorType, ImageEncoder};

    use super::{derive_image_secret, prepare_secret_photo, preview_dimensions};

    #[test]
    fn preview_is_bounded_without_changing_aspect_ratio() {
        assert_eq!(preview_dimensions(4_000, 3_000), (747, 560));
        assert_eq!(preview_dimensions(600, 400), (600, 400));
        assert_eq!(preview_dimensions(0, 0), (1, 1));
    }

    #[test]
    fn canonical_image_secret_depends_on_pixels_not_container_metadata() {
        let pixels = [
            0x10, 0x20, 0x30, 0xff, 0x40, 0x50, 0x60, 0xff, 0x70, 0x80, 0x90, 0xff, 0xa0, 0xb0,
            0xc0, 0xff,
        ];
        let first = derive_image_secret(2, 2, &pixels);
        let second = derive_image_secret(2, 2, &pixels);
        assert_eq!(
            hex::encode(first),
            "8d96ff98f464d528b9a1dd123059276dd34bf9735a5c99e2dba17273a5f8286c"
        );
        assert_eq!(first, second);

        let mut changed = pixels;
        changed[5] ^= 1;
        assert_ne!(first, derive_image_secret(2, 2, &changed));
    }

    #[test]
    fn image_file_metadata_does_not_change_the_master_secret() {
        let directory = tempfile::tempdir().unwrap();
        let plain_path = directory.path().join("plain.png");
        let metadata_path = directory.path().join("metadata.png");
        let pixels = (0..32 * 32)
            .flat_map(|index| {
                let x = (index % 32) as u8;
                let y = (index / 32) as u8;
                [x * 7, y * 5, x.wrapping_mul(11) ^ y, 0xff]
            })
            .collect::<Vec<_>>();

        PngEncoder::new(File::create(&plain_path).unwrap())
            .write_image(&pixels, 32, 32, ExtendedColorType::Rgba8)
            .unwrap();
        let mut encoder = PngEncoder::new(File::create(&metadata_path).unwrap());
        encoder
            .set_exif_metadata(b"private metadata that must not become a key".to_vec())
            .unwrap();
        encoder
            .write_image(&pixels, 32, 32, ExtendedColorType::Rgba8)
            .unwrap();

        assert_ne!(
            std::fs::read(&plain_path).unwrap(),
            std::fs::read(&metadata_path).unwrap()
        );
        let plain = prepare_secret_photo(plain_path).unwrap();
        let with_metadata = prepare_secret_photo(metadata_path).unwrap();
        assert_eq!(
            plain.master_secret().as_str(),
            with_metadata.master_secret().as_str()
        );
        assert_eq!(plain.key_id, with_metadata.key_id);
    }

    #[test]
    fn jpeg_photo_has_a_cross_platform_golden_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("photo.jpg");
        let pixels = (0..32 * 32)
            .flat_map(|index| {
                let x = (index % 32) as u8;
                let y = (index / 32) as u8;
                [x * 7, y * 5, x.wrapping_mul(y).wrapping_mul(3)]
            })
            .collect::<Vec<_>>();
        JpegEncoder::new_with_quality(File::create(&path).unwrap(), 83)
            .write_image(&pixels, 32, 32, ExtendedColorType::Rgb8)
            .unwrap();

        let photo = prepare_secret_photo(path).unwrap();
        assert_eq!(
            photo.master_secret().as_str(),
            "15e9b1e6005a3b5670784debbf5abd3e375f5be603f286fa3221a87bf982ac64"
        );
    }

    #[test]
    fn tiny_and_uniform_photo_sources_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let tiny_path = directory.path().join("tiny.png");
        PngEncoder::new(File::create(&tiny_path).unwrap())
            .write_image(&[0xff, 0, 0, 0xff], 1, 1, ExtendedColorType::Rgba8)
            .unwrap();
        assert!(prepare_secret_photo(tiny_path)
            .unwrap_err()
            .contains("at least 32 × 32 pixels"));

        let uniform_path = directory.path().join("uniform.png");
        let uniform = [0x22, 0x44, 0x66, 0xff].repeat(32 * 32);
        PngEncoder::new(File::create(&uniform_path).unwrap())
            .write_image(&uniform, 32, 32, ExtendedColorType::Rgba8)
            .unwrap();
        assert!(prepare_secret_photo(uniform_path)
            .unwrap_err()
            .contains("at least 64 distinct pixel values"));
    }

    #[test]
    fn non_photo_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("not-a-photo.txt");
        std::fs::write(&path, b"this must never become a wallet secret").unwrap();

        assert!(prepare_secret_photo(path).is_err());
    }
}
