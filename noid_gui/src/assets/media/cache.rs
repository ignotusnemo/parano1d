// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{Bundle, Manifest};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

fn directory(root: &Path) -> Result<PathBuf, String> {
    let directory = root.join("cache");
    for path in [
        &directory,
        &directory.join("metadata"),
        &directory.join("images"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(info) if !info.file_type().is_dir() => {
                return Err("Invalid asset cache directory.".into())
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err("The asset cache could not be opened.".into())
            }
            _ => {}
        }
    }
    Ok(directory)
}

fn files(directory: &Path) -> Result<Vec<(PathBuf, u64, SystemTime)>, String> {
    let mut files = Vec::new();
    for (area, extension) in [("metadata", "json"), ("images", "png")] {
        let path = directory.join(area);
        if !path.exists() {
            continue;
        }
        for entry in fs::read_dir(path).map_err(|_| "The asset cache could not be read.")? {
            if files.len() >= 32_768 {
                return Err("The asset cache contains too many files.".into());
            }
            let entry = entry.map_err(|_| "The asset cache could not be read.")?;
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) != Some(extension)
                || !path
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .is_some_and(super::digest)
            {
                continue;
            }
            let info =
                fs::symlink_metadata(&path).map_err(|_| "The asset cache could not be read.")?;
            if info.file_type().is_file() {
                files.push((
                    path,
                    info.len(),
                    info.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                ));
            }
        }
    }
    Ok(files)
}

fn reserve(directory: &Path, needed: u64, protected: BTreeSet<PathBuf>) -> Result<(), String> {
    if needed > MAX_BYTES {
        return Err("The asset exceeds the media cache limit.".into());
    }
    let mut files = files(directory)?;
    let mut total: u64 = files.iter().map(|(_, bytes, _)| bytes).sum();
    files.sort_by_key(|(_, _, time)| *time);
    for (path, bytes, _) in files {
        if total.saturating_add(needed) <= MAX_BYTES {
            break;
        }
        if protected.contains(&path) {
            continue;
        }
        fs::remove_file(path)
            .map_err(|_| "Old asset cache files could not be removed.".to_owned())?;
        total = total.saturating_sub(bytes);
    }
    if total.saturating_add(needed) > MAX_BYTES {
        return Err("The asset cache is full.".into());
    }
    Ok(())
}

pub fn load(root: &Path, hash: &str) -> Result<Bundle, String> {
    Bundle::load(root, hash).or_else(|_| Bundle::load(&directory(root)?, hash))
}

pub fn manifest(root: &Path, hash: &str) -> Result<Manifest, String> {
    super::cached_manifest(root, hash).or_else(|_| super::cached_manifest(&directory(root)?, hash))
}

pub fn save_bundle(root: &Path, bundle: &Bundle) -> Result<(), String> {
    let directory = directory(root)?;
    let hash = bundle.hash()?;
    let metadata = directory.join("metadata").join(format!("{hash}.json"));
    let mut protected = BTreeSet::from([metadata]);
    let mut needed = bundle.manifest().canonical_bytes()?.len() as u64;
    if let Some(image) = bundle.image() {
        needed += image.bytes().len() as u64;
        protected.insert(
            directory
                .join("images")
                .join(format!("{}.png", image.record().hash)),
        );
    }
    reserve(&directory, needed, protected)?;
    bundle.persist(&directory)
}

pub fn save_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    let directory = directory(root)?;
    let protected = BTreeSet::from([directory
        .join("metadata")
        .join(format!("{}.json", manifest.hash()?))]);
    reserve(
        &directory,
        manifest.canonical_bytes()?.len() as u64,
        protected,
    )?;
    super::cache_manifest(&directory, manifest)
}

pub fn clear(root: &Path) -> Result<u64, String> {
    let directory = directory(root)?;
    let bytes = files(&directory)?.iter().map(|(_, bytes, _)| bytes).sum();
    match fs::remove_dir_all(directory) {
        Ok(()) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err("The asset cache could not be cleared.".into()),
    }
}
