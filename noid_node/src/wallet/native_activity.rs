// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Local submission records retained until canonical finalization or dismissal.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use noid_poseidon2b::primitives::Address;
use noid_rpc::native_types::NativeWalletActivity;
use serde::{Deserialize, Serialize};

use super::persistence::Journal;

const MAGIC: &[u8; 8] = b"NOIDNAP1";
const MAX_ENTRIES: usize = 4096;
const MAX_ENTRY_BYTES: usize = 32 * 1024;

#[derive(Default)]
pub(super) struct Activity {
    entries: BTreeMap<[u8; 32], NativeWalletActivity>,
    dirty: BTreeSet<[u8; 32]>,
    journal: Option<Journal>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delta {
    reset: bool,
    changes: Vec<(String, Option<NativeWalletActivity>)>,
}

fn digest(value: &str) -> Result<[u8; 32], String> {
    let mut id = [0; 32];
    if value.len() != 64 || hex::decode_to_slice(value, &mut id).is_err() {
        return Err("invalid native submission identity".into());
    }
    if hex::encode(id) != value {
        return Err("noncanonical native submission identity".into());
    }
    Ok(id)
}

fn validate(entry: &NativeWalletActivity) -> Result<[u8; 32], String> {
    let preview = &entry.preview;
    let id = digest(&preview.txid)?;
    digest(&preview.plan_id)?;
    digest(&preview.parent_hash)?;
    digest(&preview.state_root)?;
    Address::parse(&preview.owner).map_err(|_| "invalid native submission owner")?;
    if preview.height == 0
        || preview.input_count == 0
        || preview.input_count > noid_tx::MAX_PAGED_SPEND_INPUTS
        || preview.output_count > noid_tx::MAX_PAGED_SPEND_OUTPUTS
        || serde_json::to_vec(entry).map_err(|e| e.to_string())?.len() > MAX_ENTRY_BYTES
    {
        return Err("native submission record exceeds wallet limits".into());
    }
    Ok(id)
}

impl Activity {
    pub(super) fn load(path: &Path, owns: impl Fn(u32, &str) -> bool) -> Result<Self, String> {
        let mut entries = BTreeMap::new();
        let journal = Journal::load(path, MAGIC, |bytes| {
            if bytes.len() > MAX_ENTRIES * (MAX_ENTRY_BYTES + 128) + 128 {
                return Err("native submission journal frame exceeds wallet limits".into());
            }
            let delta: Delta = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
            if delta.changes.len() > MAX_ENTRIES {
                return Err("native submission journal has too many changes".into());
            }
            if delta.reset {
                entries.clear();
            }
            let mut seen = BTreeSet::new();
            for (key, value) in delta.changes {
                let id = digest(&key)?;
                if !seen.insert(id) {
                    return Err("duplicate native submission journal change".into());
                }
                if let Some(value) = value {
                    if validate(&value)? != id
                        || !owns(value.preview.key_index, &value.preview.owner)
                    {
                        return Err("native submission record belongs to another wallet".into());
                    }
                    entries.insert(id, value);
                } else {
                    entries.remove(&id);
                }
            }
            if entries.len() > MAX_ENTRIES {
                return Err("native submission journal exceeds wallet limit".into());
            }
            Ok(())
        })?;
        if journal.is_none() && path.exists() {
            return Err("unsupported native submission journal format".into());
        }
        Ok(Self {
            entries,
            dirty: BTreeSet::new(),
            journal,
        })
    }

    pub(super) fn insert(&mut self, entry: NativeWalletActivity) -> Result<(), String> {
        let id = validate(&entry)?;
        if let Some(old) = self.entries.get(&id) {
            if old.preview != entry.preview {
                return Err("native submission details changed".into());
            }
            return Ok(());
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(
                "review or dismiss unconfirmed native submissions before sending more".into(),
            );
        }
        self.entries.insert(id, entry);
        self.dirty.insert(id);
        Ok(())
    }

    pub(super) fn remove(&mut self, id: [u8; 32]) {
        if self.entries.remove(&id).is_some() {
            self.dirty.insert(id);
        }
    }

    pub(super) fn records(&self) -> Vec<NativeWalletActivity> {
        let mut records: Vec<_> = self.entries.values().cloned().collect();
        records.sort_by(|a, b| {
            b.submitted_unix
                .cmp(&a.submitted_unix)
                .then_with(|| a.preview.txid.cmp(&b.preview.txid))
        });
        records
    }

    pub(super) fn save(&mut self, path: &Path) -> Result<(), String> {
        let budget = (self.entries.len() * MAX_ENTRY_BYTES) as u64;
        let reset = self
            .journal
            .as_ref()
            .is_none_or(|journal| journal.needs_compaction(budget));
        if !reset
            && self.dirty.is_empty()
            && !self
                .journal
                .as_ref()
                .is_some_and(Journal::has_pending_write)
        {
            return Ok(());
        }
        let changes = if reset {
            self.entries
                .iter()
                .map(|(id, value)| (hex::encode(id), Some(value.clone())))
                .collect()
        } else {
            self.dirty
                .iter()
                .map(|id| (hex::encode(id), self.entries.get(id).cloned()))
                .collect()
        };
        let bytes = serde_json::to_vec(&Delta { reset, changes }).map_err(|e| e.to_string())?;
        Journal::save(&mut self.journal, path, MAGIC, &bytes, reset)?;
        self.dirty.clear();
        Ok(())
    }
}
