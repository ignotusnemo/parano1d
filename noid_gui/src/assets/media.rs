// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Content-addressed public descriptions and static images for native assets.

use iced::widget::image::Handle;
use image::{ImageEncoder, ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};

#[path = "media/cache.rs"]
pub(crate) mod cache;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 8192;
const MAX_INPUT_DIMENSION: u32 = 4096;

#[path = "../market_data/server.rs"]
pub mod history;
#[path = "media/library.rs"]
pub mod library;
#[path = "media/service.rs"]
pub mod service;
#[path = "media/transport.rs"]
pub mod transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Token,
    Collection,
    Nft,
}

impl Kind {
    fn dimension(self) -> u32 {
        if self == Self::Nft {
            2048
        } else {
            512
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub hash: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u8,
    pub kind: Kind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub image: Option<Image>,
}

fn safe_text(value: &str, bytes: usize, characters: usize, multiline: bool) -> bool {
    value.len() <= bytes
        && value.chars().count() <= characters
        && value.trim() == value
        && !value.chars().any(|c| {
            (c.is_control() && !(multiline && c == '\n'))
                || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        })
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn content_hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn cached_manifest(directory: &Path, hash: &str) -> Result<Manifest, String> {
    if !digest(hash) {
        return Err("Invalid metadata hash.".into());
    }
    let bytes = read_bounded(
        &directory.join("metadata").join(format!("{hash}.json")),
        MAX_MANIFEST_BYTES,
    )?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid asset metadata.")?;
    if manifest.hash()? != hash {
        return Err("The cached metadata differs from its identity.".into());
    }
    Ok(manifest)
}

pub(crate) fn cache_manifest(directory: &Path, manifest: &Manifest) -> Result<(), String> {
    save_immutable(
        &directory
            .join("metadata")
            .join(format!("{}.json", manifest.hash()?)),
        &manifest.canonical_bytes()?,
        MAX_MANIFEST_BYTES,
    )
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 || self.name.is_empty() || !safe_text(&self.name, 256, 64, false) {
            return Err("Enter a name of up to 64 characters.".into());
        }
        if !safe_text(&self.description, 4096, 1000, true) {
            return Err("Use up to 1,000 characters for the description.".into());
        }
        if self
            .website
            .as_deref()
            .is_some_and(|url| !valid_website(url))
        {
            return Err(
                "Enter a valid https:// project website without a username or password.".into(),
            );
        }
        if self.kind == Kind::Token {
            let symbol = self.symbol.as_deref().unwrap_or_default();
            if symbol.is_empty()
                || symbol.len() > 12
                || !symbol.as_bytes()[0].is_ascii_uppercase()
                || !symbol
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                || symbol == "NOID"
            {
                return Err("Use 1–12 uppercase letters or digits for the ticker, starting with a letter. NOID is reserved.".into());
            }
        } else if self.symbol.is_some() {
            return Err("Only fungible tokens have a ticker.".into());
        }
        if let Some(image) = &self.image {
            if !digest(&image.hash)
                || image.media_type != "image/png"
                || image.width == 0
                || image.height == 0
                || image.width > self.kind.dimension()
                || image.height > self.kind.dimension()
                || image.bytes == 0
                || image.bytes as usize > MAX_IMAGE_BYTES
            {
                return Err("The asset image has an unsupported format or size.".into());
            }
        } else if self.kind == Kind::Nft {
            return Err("Choose an image for this NFT.".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err("The asset description exceeds its size limit.".into());
        }
        Ok(bytes)
    }

    pub fn hash(&self) -> Result<String, String> {
        Ok(content_hash(
            b"Parano1d/native-metadata/v1\0",
            &self.canonical_bytes()?,
        ))
    }
}

pub fn valid_website(value: &str) -> bool {
    safe_text(value, 2048, 2048, false)
        && reqwest::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.has_host()
                && url.username().is_empty()
                && url.password().is_none()
        })
}

#[derive(Debug, Clone)]
pub struct PreparedImage {
    record: Image,
    png: Vec<u8>,
    handle: Handle,
    display_bytes: usize,
}

impl PreparedImage {
    pub fn record(&self) -> &Image {
        &self.record
    }

    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.png
    }

    pub fn memory_bytes(&self) -> usize {
        self.png.len() + self.display_bytes + 8192
    }

    pub fn from_file(path: &Path, kind: Kind) -> Result<Self, String> {
        Self::prepare(&read_bounded(path, MAX_IMAGE_BYTES)?, kind)
    }

    pub fn prepare(bytes: &[u8], kind: Kind) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
            return Err("Choose a PNG, JPEG or WebP image of up to 4 MB.".into());
        }
        let mut reader = ImageReader::new(Cursor::new(bytes))
            .with_guessed_format()
            .map_err(|_| "The image format could not be read.")?;
        if !matches!(
            reader.format(),
            Some(ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP)
        ) {
            return Err("Choose a PNG, JPEG or WebP image.".into());
        }
        reader.limits(decode_limits(MAX_INPUT_DIMENSION));
        let image = reader
            .decode()
            .map_err(|_| "The image could not be decoded within its size limit.")?;
        let image = if image.width() > kind.dimension() || image.height() > kind.dimension() {
            image.thumbnail(kind.dimension(), kind.dimension())
        } else {
            image
        }
        .into_rgba8();
        let (width, height) = image.dimensions();
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(
                image.as_raw(),
                width,
                height,
                image::ExtendedColorType::Rgba8,
            )
            .map_err(|_| "The image could not be prepared.")?;
        if png.len() > MAX_IMAGE_BYTES {
            return Err("The prepared image exceeds 4 MB. Choose a smaller image.".into());
        }
        let (handle, display_bytes) = display_image(image);
        Ok(Self {
            record: Image {
                hash: content_hash(b"Parano1d/native-image/v1\0", &png),
                media_type: "image/png".into(),
                width,
                height,
                bytes: png.len() as u32,
            },
            png,
            handle,
            display_bytes,
        })
    }

    fn verify(record: &Image, png: &[u8], kind: Kind) -> Result<Self, String> {
        if png.len() != record.bytes as usize
            || png.len() > MAX_IMAGE_BYTES
            || content_hash(b"Parano1d/native-image/v1\0", png) != record.hash
        {
            return Err("The image differs from the asset's metadata.".into());
        }
        let mut reader = ImageReader::with_format(Cursor::new(png), ImageFormat::Png);
        reader.limits(decode_limits(kind.dimension()));
        let image = reader
            .decode()
            .map_err(|_| "The asset image could not be decoded within its size limit.")?
            .into_rgba8();
        if image.dimensions() != (record.width, record.height) {
            return Err("The image dimensions differ from the asset's metadata.".into());
        }
        let (handle, display_bytes) = display_image(image);
        Ok(Self {
            record: record.clone(),
            png: png.to_vec(),
            handle,
            display_bytes,
        })
    }
}

fn display_image(image: image::RgbaImage) -> (Handle, usize) {
    let image = if image.width() > 512 || image.height() > 512 {
        image::DynamicImage::ImageRgba8(image)
            .thumbnail(512, 512)
            .into_rgba8()
    } else {
        image
    };
    let bytes = image.as_raw().len();
    (
        Handle::from_rgba(image.width(), image.height(), image.into_raw()),
        bytes,
    )
}

fn decode_limits(dimension: u32) -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(dimension);
    limits.max_image_height = Some(dimension);
    limits.max_alloc = Some(64 * 1024 * 1024);
    limits
}

#[derive(Debug, Clone)]
pub struct Bundle {
    manifest: Manifest,
    image: Option<Arc<PreparedImage>>,
}

impl Bundle {
    pub fn new(
        kind: Kind,
        name: &str,
        symbol: Option<&str>,
        description: &str,
        image: Option<Arc<PreparedImage>>,
    ) -> Result<Self, String> {
        let manifest = Manifest {
            schema: 1,
            kind,
            name: name.trim().into(),
            symbol: symbol.map(|s| s.trim().to_ascii_uppercase()),
            description: description.replace("\r\n", "\n").trim().into(),
            website: None,
            image: image.as_ref().map(|image| image.record.clone()),
        };
        manifest.validate()?;
        Ok(Self { manifest, image })
    }

    pub fn with_website(mut self, website: &str) -> Result<Self, String> {
        let website = website.trim();
        self.manifest.website = if website.is_empty() {
            None
        } else {
            if !valid_website(website) {
                return Err(
                    "Enter a valid https:// project website without a username or password.".into(),
                );
            }
            Some(
                reqwest::Url::parse(website)
                    .map_err(|e| e.to_string())?
                    .to_string(),
            )
        };
        self.manifest.validate()?;
        Ok(self)
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn image(&self) -> Option<Arc<PreparedImage>> {
        self.image.clone()
    }

    pub fn hash(&self) -> Result<String, String> {
        self.manifest.hash()
    }

    pub fn from_untrusted(
        expected: &str,
        json: &[u8],
        image: Option<&[u8]>,
    ) -> Result<Self, String> {
        if !digest(expected) || json.len() > MAX_MANIFEST_BYTES {
            return Err("The asset metadata exceeds its format or size limit.".into());
        }
        let manifest: Manifest =
            serde_json::from_slice(json).map_err(|_| "The asset metadata is not supported.")?;
        if manifest.hash()? != expected {
            return Err("The metadata differs from the hash recorded in State.".into());
        }
        let image = match (&manifest.image, image) {
            (Some(record), Some(png)) => {
                Some(Arc::new(PreparedImage::verify(record, png, manifest.kind)?))
            }
            (None, None) => None,
            _ => return Err("The asset image is missing or unexpected.".into()),
        };
        Ok(Self { manifest, image })
    }

    pub fn persist(&self, directory: &Path) -> Result<(), String> {
        let json = self.manifest.canonical_bytes()?;
        let hash = self.hash()?;
        if let Some(image) = &self.image {
            save_immutable(
                &directory
                    .join("images")
                    .join(format!("{}.png", image.record.hash)),
                image.bytes(),
                MAX_IMAGE_BYTES,
            )?;
        }
        save_immutable(
            &directory.join("metadata").join(format!("{hash}.json")),
            &json,
            MAX_MANIFEST_BYTES,
        )
    }

    pub fn load(directory: &Path, expected: &str) -> Result<Self, String> {
        if !digest(expected) {
            return Err("The asset metadata hash is invalid.".into());
        }
        let json = read_bounded(
            &directory.join("metadata").join(format!("{expected}.json")),
            MAX_MANIFEST_BYTES,
        )?;
        let manifest: Manifest =
            serde_json::from_slice(&json).map_err(|_| "The cached asset metadata is invalid.")?;
        if manifest.hash()? != expected {
            return Err("The cached metadata differs from State.".into());
        }
        let image = manifest
            .image
            .as_ref()
            .map(|image| {
                read_bounded(
                    &directory.join("images").join(format!("{}.png", image.hash)),
                    MAX_IMAGE_BYTES,
                )
            })
            .transpose()?;
        Self::from_untrusted(expected, &json, image.as_deref())
    }
}

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "The asset file could not be read.")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("The asset file exceeds its type or size limit.".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "The asset file could not be opened.")?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "The asset file could not be read.")?;
    if bytes.len() > limit {
        return Err("The asset file exceeds its size limit.".into());
    }
    Ok(bytes)
}

pub(crate) fn save_immutable(path: &Path, bytes: &[u8], limit: usize) -> Result<(), String> {
    let parent = path.parent().ok_or("The asset cache path is invalid.")?;
    fs::create_dir_all(parent).map_err(|_| "The asset cache could not be created.")?;
    let temporary: PathBuf =
        parent.join(format!(".{}.tmp", hex::encode(rand::random::<[u8; 16]>())));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| "The asset cache could not be written.")?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "The asset cache could not be saved.")?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| "The asset cache directory could not be saved.")?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_bounded(path, limit)? == bytes {
                    Ok(())
                } else {
                    Err("The asset cache contains different data for this hash.".into())
                }
            }
            Err(_) => Err("The asset cache file could not be committed.".into()),
        }
    })();
    let _ = fs::remove_file(temporary);
    result
}

#[derive(Debug, Default)]
pub struct Draft {
    pub image: Option<Arc<PreparedImage>>,
    pub loading: bool,
    pub error: Option<String>,
    pub generation: u64,
}

impl Draft {
    pub fn cancel_loading(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.loading = false;
    }

    pub fn begin(&mut self) -> u64 {
        self.cancel_loading();
        self.loading = true;
        self.error = None;
        self.generation
    }

    pub fn finish(&mut self, generation: u64, result: Result<Option<Arc<PreparedImage>>, String>) {
        if generation != self.generation || !self.loading {
            return;
        }
        self.loading = false;
        match result {
            Ok(Some(image)) => {
                self.image = Some(image);
                self.error = None;
            }
            Ok(None) => {}
            Err(error) => self.error = Some(error),
        }
    }

    pub fn clear(&mut self) {
        self.cancel_loading();
        self.image = None;
        self.error = None;
    }
}
