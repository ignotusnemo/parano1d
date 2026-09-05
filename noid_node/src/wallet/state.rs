// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! In-memory wallet state.
//!
//! Simplified design (no passwords):
//! - On first start: generate random master secret, save to wallet.key
//! - On subsequent starts: load master secret from wallet.key
//! - Wallet is always "unlocked" once loaded (no lock/unlock cycle)
//! - Only the active address's UTXOs are cached in memory
//! - The cache is replaced from an exact, verified owner-index snapshot

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use noid_chain::storage::VerifiedOwnerSnapshot;
use noid_poseidon2b::primitives::{Address, SpendSecret};
use zeroize::Zeroizing;

use super::keystore::{Keystore, KeystoreError, MasterSecret};
use super::persistence::{legacy_backup_path, Journal, ReceiptMap, HISTORY_MAGIC, RECEIPTS_MAGIC};

/// Maximum number of local addresses the built-in wallet will derive.
/// Valid key indices are `0..MAX_WALLET_ADDRESSES`.
pub const MAX_WALLET_ADDRESSES: u32 = 100_000;

// ---------------------------------------------------------------------------
// TxHistoryEntry
// ---------------------------------------------------------------------------

/// Direction of a historical transaction relative to this wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TxDirection {
    Sent,
    Received,
}

/// A record of a past transaction involving this wallet.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxHistoryEntry {
    /// Transaction body hash (32 bytes).
    pub tx_hash: [u8; 32],
    /// Exact block which confirmed this entry. Older wallet-history files did
    /// not persist it, so `None` is retained as a migration-safe legacy value.
    /// New coinbase records use this identity to distinguish a canonical
    /// reward from a locally mined block later displaced by a reorganization.
    #[serde(default)]
    pub block_hash: Option<[u8; 32]>,
    /// Block height at which this tx was confirmed.
    pub height: u64,
    /// Whether we sent or received in this tx.
    pub direction: TxDirection,
    /// True only for the canonical coinbase at logical transaction zero.
    #[serde(default)]
    pub is_coinbase: bool,
    /// Net amount in μNOID (sent: net sent, received: total received).
    pub amount_micronoid: u64,
    /// Counterparty address (None if unknown).
    pub peer_address: Option<[u8; 32]>,
    /// Block timestamp (Unix seconds).
    pub timestamp: u64,
    /// Which of our addresses was involved in this tx.
    pub own_address: Option<String>,
    /// Key index of that address.
    pub own_key_index: Option<u32>,
}

// ---------------------------------------------------------------------------
// WalletUtxo
// ---------------------------------------------------------------------------

/// A single unspent output owned by this wallet.
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    /// Global slot index in the chain state.
    pub slot_index: u32,
    /// Value in μNOID.
    pub value: u64,
    /// Incarnation assigned when this UTXO was minted: the monotone
    /// alloc-counter value for user mints, or the height-tagged coinbase
    /// creation id (`COINBASE_CREATION_TAG | mint_height`) for coinbase.
    /// This must be copied into every spending [`noid_tx::TxInput`].
    pub creation_id: u64,
    /// The 32-byte address that owns this slot.
    pub address: Address,
    /// Key index used to derive this address.
    pub key_index: u32,
    /// Block height at which this UTXO was confirmed.
    pub confirmed_height: u64,
}

/// Durable chain identity to which the active-address cache is bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveWalletSnapshot {
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
}

// ---------------------------------------------------------------------------
// WalletState
// ---------------------------------------------------------------------------

/// Live in-memory wallet state.
///
/// The master secret is always loaded (no lock/unlock without passwords).
pub struct WalletState {
    /// Path to the key file on disk.
    pub keystore_path: PathBuf,
    /// Master secret (always present, loaded from disk at startup).
    secret: MasterSecret,
    /// UTXOs owned by the active address only (slot_index → utxo).
    pub utxos: HashMap<u32, WalletUtxo>,
    /// Next unused key index.
    pub next_index: u32,
    /// Exact durable snapshot backing `utxos`. `None` until the first reload.
    pub active_snapshot: Option<ActiveWalletSnapshot>,
    /// Transaction history (most recent last).
    pub history: Vec<TxHistoryEntry>,
    /// Cached different-address receipts: txid → serialized ParanoidReceipt.
    /// Same-owner consolidations are omitted.
    pub receipts: ReceiptMap,
    /// A failed durable write is retried by the next accepted block.
    pub(super) receipts_dirty: bool,
    /// Pending-send ownership and confirmation metadata awaiting durable write.
    pub(super) history_dirty: bool,
    history_dirty_from: Option<usize>,
    receipts_journal: Option<Journal>,
    history_journal: Option<Journal>,
    /// Output slots claimed by pending (submitted but not yet confirmed) txs.
    /// Used to avoid SlotConflict when retrying or sending multiple txs.
    pub pending_output_slots: std::collections::HashSet<u32>,
    /// Input slots being spent by pending (submitted but not yet confirmed) txs.
    /// Used to avoid double-spending the same UTXO when a send is retried or
    /// another send starts before the first transaction is confirmed.
    pub pending_input_slots: std::collections::HashSet<u32>,
    /// The ACTIVE address key index. One owner per transaction (consensus
    /// rule): sends spend ONLY this address's UTXOs and change returns to it.
    /// Inactive addresses are not scanned or cached.
    pub active_index: u32,
    /// RPC cache identity. The random epoch prevents cache reuse after a node
    /// restart or wallet replacement; the counter changes with UTXO metadata
    /// or pending-input reservations, even at an unchanged chain height.
    utxo_revision_epoch: u128,
    utxo_revision: u64,
}

impl WalletState {
    /// Create or load the wallet from `key_path`.
    ///
    /// - If the file does not exist: generate a new random secret and save it.
    /// - If the file exists: load the existing secret.
    pub fn create_or_load(key_path: PathBuf) -> Result<Self, KeystoreError> {
        let ks = Keystore::new(&key_path);
        let secret = if ks.exists() {
            tracing::info!(path = %key_path.display(), "loading wallet");
            ks.load_plain()?
        } else {
            tracing::info!(path = %key_path.display(), "creating new wallet");
            ks.create_plain()?
        };

        let mut wallet = Self {
            keystore_path: key_path,
            secret,
            utxos: HashMap::new(),
            next_index: 1,
            active_snapshot: None,
            history: Vec::new(),
            receipts: ReceiptMap::default(),
            receipts_dirty: false,
            history_dirty: false,
            history_dirty_from: None,
            receipts_journal: None,
            history_journal: None,
            pending_output_slots: std::collections::HashSet::new(),
            pending_input_slots: std::collections::HashSet::new(),
            active_index: 0,
            utxo_revision_epoch: rand::random(),
            utxo_revision: 0,
        };
        wallet.load_metadata();
        wallet.load_receipts().map_err(KeystoreError::Artifact)?;
        wallet.load_history().map_err(KeystoreError::Artifact)?;
        Ok(wallet)
    }

    /// Address at a specific key index.
    pub fn address_at(&self, index: u32) -> Address {
        self.secret.derive_address(index)
    }

    pub(crate) fn invalidate_utxo_snapshot(&mut self) {
        if let Some(next) = self.utxo_revision.checked_add(1) {
            self.utxo_revision = next;
        } else {
            self.utxo_revision_epoch = rand::random();
            self.utxo_revision = 0;
        }
    }

    pub(super) fn utxo_snapshot_revision(&self) -> String {
        format!(
            "{:032x}-{:016x}",
            self.utxo_revision_epoch, self.utxo_revision
        )
    }

    /// Spend secret for a specific key index.
    pub(super) fn spend_secret_for(&self, key_index: u32) -> SpendSecret {
        self.secret.derive_spend_secret(key_index)
    }

    /// The ACTIVE address (spends originate here; change returns here).
    pub fn active_address(&self) -> Address {
        self.secret.derive_address(self.active_index)
    }

    /// Preview an address already generated on this machine without mutation.
    pub fn preview_generated_index(&self, index: u32) -> Result<Address, &'static str> {
        if index >= self.next_index {
            return Err("active address index has not been generated");
        }
        if index != self.active_index && self.has_pending_activity() {
            return Err("cannot switch active address while a wallet transaction is pending");
        }
        Ok(self.secret.derive_address(index))
    }

    /// Persist exactly one new inactive address. The active owner, UTXO cache,
    /// pending transaction state, and mining payout remain unchanged.
    pub fn create_next_inactive_address(&mut self) -> Result<(u32, Address), String> {
        if self.next_index >= MAX_WALLET_ADDRESSES {
            return Err("wallet address limit reached".into());
        }
        let index = self.next_index;
        let address = self.secret.derive_address(index);
        let next_index = index + 1;
        self.persist_metadata(next_index, self.active_index)?;
        self.next_index = next_index;
        Ok((index, address))
    }

    pub fn has_pending_activity(&self) -> bool {
        !self.pending_input_slots.is_empty() || !self.pending_output_slots.is_empty()
    }

    /// Persist a contiguous prefix of funded addresses discovered from the
    /// live owner index without activating or loading any inactive address.
    pub fn commit_discovered_next_index(
        &mut self,
        expected_active_index: u32,
        expected_next_index: u32,
        discovered_next_index: u32,
    ) -> Result<(), String> {
        if self.active_index != expected_active_index || self.next_index != expected_next_index {
            return Err("wallet address selection changed during address discovery".into());
        }
        if self.has_pending_activity() {
            return Err("cannot discover addresses while a wallet transaction is pending".into());
        }
        if discovered_next_index < self.next_index || discovered_next_index > MAX_WALLET_ADDRESSES {
            return Err("discovered address range is invalid".into());
        }
        if discovered_next_index == self.next_index {
            return Ok(());
        }
        self.persist_metadata(discovered_next_index, self.active_index)?;
        self.next_index = discovered_next_index;
        Ok(())
    }

    /// Confirmed balance of the ACTIVE address in μNOID.
    pub fn balance(&self) -> u64 {
        self.utxos
            .values()
            .map(|u| u.value)
            .fold(0u64, |a, v| a.saturating_add(v))
    }

    /// Replace the active cache from an owner-index view that was verified
    /// against one atomic durable chain snapshot.
    pub fn commit_verified_activation(
        &mut self,
        expected_active_index: u32,
        expected_next_index: u32,
        target_index: u32,
        queried_owner: [u8; 32],
        snapshot: VerifiedOwnerSnapshot,
        reserved_input_slots: &HashSet<u32>,
        reserved_output_slots: &HashSet<u32>,
    ) -> Result<(), String> {
        if self.active_index != expected_active_index || self.next_index != expected_next_index {
            return Err(
                "wallet address selection changed during owner snapshot lookup".to_string(),
            );
        }
        if target_index != self.active_index && self.has_pending_activity() {
            return Err(
                "cannot switch active address while a wallet transaction is pending".into(),
            );
        }
        if target_index >= self.next_index {
            return Err("active address index has not been generated".to_string());
        }
        let active_address = self.secret.derive_address(target_index);
        if active_address.0 != queried_owner {
            return Err("owner snapshot does not match activation preview".to_string());
        }
        if snapshot.owner != queried_owner {
            return Err("verified snapshot belongs to another owner".to_string());
        }

        let mut new_utxos = HashMap::with_capacity(snapshot.utxos.len());
        for utxo in snapshot.utxos.iter() {
            new_utxos.insert(
                utxo.slot_index,
                WalletUtxo {
                    slot_index: utxo.slot_index,
                    value: utxo.amount,
                    creation_id: utxo.creation_id,
                    address: active_address,
                    key_index: target_index,
                    confirmed_height: snapshot.height,
                },
            );
        }
        let new_snapshot = ActiveWalletSnapshot {
            height: snapshot.height,
            tip_hash: snapshot.tip_hash,
            state_root: snapshot.state_root,
            log_slots: snapshot.log_slots,
            active_slot_count: snapshot.active_slot_count,
            alloc_counter: snapshot.alloc_counter,
        };

        // Persist first. If the filesystem operation fails, the live wallet
        // remains byte-for-byte on the old account/cache.
        if target_index != self.active_index {
            self.persist_metadata(self.next_index, target_index)?;
        }
        self.active_index = target_index;
        self.utxos = new_utxos;
        self.active_snapshot = Some(new_snapshot);
        self.pending_input_slots = self
            .utxos
            .keys()
            .filter(|slot| reserved_input_slots.contains(slot))
            .copied()
            .collect();
        self.pending_output_slots
            .retain(|slot| reserved_output_slots.contains(slot));
        self.invalidate_utxo_snapshot();
        Ok(())
    }

    /// Get a cached receipt by txid.
    pub fn get_receipt(&self, tx_hash: &[u8; 32]) -> Option<&Vec<u8>> {
        self.receipts.get(tx_hash)
    }

    pub(super) fn mark_history_dirty(&mut self, from: usize) {
        self.history_dirty = true;
        self.history_dirty_from = Some(self.history_dirty_from.map_or(from, |old| old.min(from)));
    }

    /// Record an outgoing send in history (height=0 until confirmed).
    pub fn record_pending_send(
        &mut self,
        tx_hash: [u8; 32],
        amount_micronoid: u64,
        to_address: [u8; 32],
    ) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.history.push(TxHistoryEntry {
            tx_hash,
            block_hash: None,
            height: 0, // updated to real height when block is confirmed
            direction: TxDirection::Sent,
            is_coinbase: false,
            amount_micronoid,
            peer_address: Some(to_address),
            timestamp: now,
            own_address: Some(self.active_address().to_bech32()),
            own_key_index: Some(self.active_index),
        });
        self.mark_history_dirty(self.history.len() - 1);
        self.save_history()
    }

    /// Remove a pending send that never entered the mempool.
    pub fn remove_pending_send(&mut self, tx_hash: &[u8; 32]) -> Result<(), String> {
        let before = self.history.len();
        self.history
            .retain(|entry| !(&entry.tx_hash == tx_hash && entry.height == 0));
        if self.history.len() != before {
            self.mark_history_dirty(0);
            self.save_history()?;
        }
        Ok(())
    }

    /// Update the height of a pending (height=0) tx once it is confirmed.
    /// The block-level caller persists the complete history once after all
    /// transactions have been applied, avoiding one fsync per transaction.
    pub fn confirm_pending_tx(
        &mut self,
        tx_hash: &[u8; 32],
        confirmed_height: u64,
        confirmed_block_hash: [u8; 32],
    ) -> bool {
        for (index, entry) in self.history.iter_mut().enumerate() {
            if &entry.tx_hash == tx_hash && entry.height == 0 {
                entry.height = confirmed_height;
                entry.block_hash = Some(confirmed_block_hash);
                self.mark_history_dirty(index);
                return true;
            }
        }
        false
    }

    /// Register output slots as pending (tx submitted to mempool).
    /// Used to avoid SlotConflict when retrying or calling wallet_send concurrently.
    pub fn add_pending_outputs(&mut self, slot_indices: &[u32]) {
        for &slot in slot_indices {
            self.pending_output_slots.insert(slot);
        }
    }

    /// Clear pending output slots for a confirmed or evicted tx.
    pub fn remove_pending_outputs(&mut self, slot_indices: &[u32]) {
        for slot in slot_indices {
            self.pending_output_slots.remove(slot);
        }
    }

    /// Register input slots as pending (tx submitted to mempool).
    /// Used to prevent a subsequent round from double-spending the same UTXOs
    /// before the first TX is confirmed.
    pub fn add_pending_inputs(&mut self, slot_indices: &[u32]) {
        let mut changed = false;
        for &slot in slot_indices {
            changed |= self.pending_input_slots.insert(slot);
        }
        if changed {
            self.invalidate_utxo_snapshot();
        }
    }

    /// Release input slots reserved immediately before mempool admission.
    pub fn remove_pending_inputs(&mut self, slot_indices: &[u32]) {
        let mut changed = false;
        for slot in slot_indices {
            changed |= self.pending_input_slots.remove(slot);
        }
        if changed {
            self.invalidate_utxo_snapshot();
        }
    }

    /// Simple largest-first coin selection.
    /// Returns `(selected UTXOs, change_amount)` or `None` if insufficient funds.
    ///
    /// **Excludes UTXOs whose slots are already in `pending_input_slots`.**
    /// This prevents a second rapid `wallet_send` from trying to spend the same
    /// UTXO as a first send that is still waiting for mempool admission or
    /// block confirmation. Without this filter the second send hits a
    /// `SlotConflict` error in the mempool even though the wallet has balance.
    pub fn select_utxos(&self, target: u64, fee: u64) -> Option<(Vec<&WalletUtxo>, u64)> {
        let needed = target.checked_add(fee)?;
        // `utxos` contains the active owner only. Filter out outputs already
        // being spent by a pending transaction.
        let mut available: Vec<&WalletUtxo> = self
            .utxos
            .values()
            .filter(|u| !self.pending_input_slots.contains(&u.slot_index))
            .collect();
        // Prefer an exact one-input payment before the largest-first prefix.
        // Besides avoiding an unnecessary change output, this lets an explicit
        // fee that is valid for 1 -> 1 remain usable when a larger UTXO would
        // require the more expensive 1 -> 2 shape.
        if let Some(exact) = available
            .iter()
            .copied()
            .filter(|utxo| utxo.value == needed)
            .min_by_key(|utxo| utxo.slot_index)
        {
            return Some((vec![exact], 0));
        }

        // Only the bounded largest-first prefix can be consumed. Partition
        // before sorting it rather than sorting the entire active wallet.
        // Ascending slot order is also ascending (segment, slot) order.
        let selection_key = |u: &&WalletUtxo| (std::cmp::Reverse(u.value), u.slot_index);
        let input_limit = noid_tx::MAX_PAGED_SPEND_INPUTS;
        if available.len() > input_limit {
            available.select_nth_unstable_by_key(input_limit, selection_key);
            available.truncate(input_limit);
        }
        available.sort_unstable_by_key(selection_key);

        let mut selected = Vec::new();
        let mut total = 0u64;
        for utxo in available.into_iter().take(noid_tx::MAX_PAGED_SPEND_INPUTS) {
            selected.push(utxo);
            total = total.checked_add(utxo.value)?;
            if total >= needed {
                return Some((selected, total - needed));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Receipt persistence
// ---------------------------------------------------------------------------

/// Local receipt journal path. Legacy JSON is migrated on the first write.
fn receipts_path(wallet_key_path: &Path) -> PathBuf {
    wallet_key_path.with_extension("receipts")
}

/// Local history journal path. Legacy JSON is migrated on the first write.
fn history_path(wallet_key_path: &Path) -> PathBuf {
    wallet_key_path.with_extension("history")
}

/// Path for lightweight wallet metadata (JSON format, next to wallet key).
fn metadata_path(wallet_key_path: &Path) -> PathBuf {
    wallet_key_path.with_extension("meta")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WalletMetadata {
    next_index: u32,
    /// The ACTIVE address key index (one-owner-per-tx model: sends spend
    /// from this address only; change returns to it).
    active_index: u32,
}

const MASTER_SECRET_HEX_LEN: usize = 64;

/// Return the one 32-byte master secret that deterministically derives every
/// wallet address. The GUI displays this explicit export and never invents a
/// second backup-file format.
pub fn export_generated_master_secret(wallet_key_path: &Path) -> Result<Zeroizing<String>, String> {
    Keystore::new(wallet_key_path)
        .export_master_secret_hex()
        .map_err(|error| format!("export generated master secret: {error}"))
}

/// Replace the generated master secret and reset the local address cursor to
/// address zero. Old wallet records are transactionally moved aside only for
/// rollback during this call and are deleted before success is returned.
pub fn import_generated_master_secret(
    wallet_key_path: &Path,
    master_secret: &str,
) -> Result<(), String> {
    let normalized = Zeroizing::new(
        master_secret
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>(),
    );
    if normalized.len() != MASTER_SECRET_HEX_LEN {
        return Err("Master secret must contain exactly 64 hexadecimal characters.".into());
    }
    let mut decoded = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(normalized.as_bytes(), &mut *decoded)
        .map_err(|_| "Master secret contains a non-hexadecimal character.".to_string())?;
    let key_bytes = Keystore::encode_plain_file(&decoded);
    let metadata_bytes = serde_json::to_vec(&WalletMetadata {
        next_index: 1,
        active_index: 0,
    })
    .map_err(|error| format!("encode imported wallet metadata: {error}"))?;

    let parent = wallet_key_path
        .parent()
        .ok_or_else(|| "Wallet key path has no parent directory.".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create wallet directory {}: {error}", parent.display()))?;

    let staged_key = parent.join(format!(
        ".wallet-import-{:032x}.key",
        rand::random::<u128>()
    ));
    let staged_metadata = parent.join(format!(
        ".wallet-import-{:032x}.meta",
        rand::random::<u128>()
    ));
    if let Err(error) =
        persist_owner_only_atomically(&staged_key, &key_bytes, "staged master secret")
    {
        let _ = std::fs::remove_file(&staged_key);
        return Err(error);
    }
    if let Err(error) =
        persist_owner_only_atomically(&staged_metadata, &metadata_bytes, "staged wallet metadata")
    {
        let _ = std::fs::remove_file(&staged_key);
        let _ = std::fs::remove_file(&staged_metadata);
        return Err(error);
    }
    if let Err(error) = Keystore::new(&staged_key).load_plain() {
        let _ = std::fs::remove_file(&staged_key);
        let _ = std::fs::remove_file(&staged_metadata);
        return Err(format!("validate imported master secret: {error}"));
    }

    let rollback = parent.join(format!(
        ".wallet-import-rollback-{:032x}",
        rand::random::<u128>()
    ));
    if let Err(error) = std::fs::create_dir(&rollback) {
        let _ = std::fs::remove_file(&staged_key);
        let _ = std::fs::remove_file(&staged_metadata);
        return Err(format!(
            "create temporary wallet rollback directory {}: {error}",
            rollback.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) =
            std::fs::set_permissions(&rollback, std::fs::Permissions::from_mode(0o700))
        {
            let _ = std::fs::remove_file(&staged_key);
            let _ = std::fs::remove_file(&staged_metadata);
            let _ = std::fs::remove_dir(&rollback);
            return Err(format!(
                "protect temporary wallet rollback directory {}: {error}",
                rollback.display()
            ));
        }
    }

    let artifacts = [
        wallet_key_path.to_path_buf(),
        metadata_path(wallet_key_path),
        history_path(wallet_key_path),
        receipts_path(wallet_key_path),
        legacy_backup_path(&history_path(wallet_key_path)),
        legacy_backup_path(&receipts_path(wallet_key_path)),
    ];
    let artifact_existed: [bool; 6] = std::array::from_fn(|index| artifacts[index].exists());
    let stage_old = (|| {
        for source in &artifacts {
            if !source.exists() {
                continue;
            }
            let name = source
                .file_name()
                .ok_or_else(|| format!("wallet artifact {} has no file name", source.display()))?;
            std::fs::rename(source, rollback.join(name)).map_err(|error| {
                format!(
                    "stage previous wallet artifact {} for replacement: {error}",
                    source.display()
                )
            })?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = stage_old {
        let restore = restore_import_rollback(&artifacts, &artifact_existed, &rollback);
        let _ = std::fs::remove_file(&staged_key);
        let _ = std::fs::remove_file(&staged_metadata);
        let _ = std::fs::remove_dir_all(&rollback);
        return match restore {
            Ok(()) => Err(error),
            Err(restore_error) => Err(format!("{error}; rollback failed: {restore_error}")),
        };
    }

    let install = (|| {
        std::fs::rename(&staged_key, wallet_key_path)
            .map_err(|error| format!("install imported master secret: {error}"))?;
        std::fs::rename(&staged_metadata, metadata_path(wallet_key_path))
            .map_err(|error| format!("install reset wallet metadata: {error}"))?;
        sync_directory(parent, "wallet directory")
    })();
    if let Err(error) = install {
        let restore = restore_import_rollback(&artifacts, &artifact_existed, &rollback);
        let _ = std::fs::remove_file(&staged_key);
        let _ = std::fs::remove_file(&staged_metadata);
        let _ = std::fs::remove_dir_all(&rollback);
        return match restore {
            Ok(()) => Err(error),
            Err(restore_error) => Err(format!("{error}; rollback failed: {restore_error}")),
        };
    }

    std::fs::remove_dir_all(&rollback).map_err(|error| {
        format!(
            "discard previous master secret after import {}: {error}",
            rollback.display()
        )
    })?;
    sync_directory(parent, "wallet directory")
}

fn restore_import_rollback(
    artifacts: &[PathBuf],
    artifact_existed: &[bool],
    rollback: &Path,
) -> Result<(), String> {
    for (target, existed) in artifacts.iter().zip(artifact_existed) {
        let name = target
            .file_name()
            .ok_or_else(|| format!("wallet artifact {} has no file name", target.display()))?;
        let staged = rollback.join(name);
        if *existed && staged.exists() {
            match std::fs::remove_file(target) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "remove partially imported wallet artifact {}: {error}",
                        target.display()
                    ));
                }
            }
            std::fs::rename(&staged, target).map_err(|error| {
                format!(
                    "restore previous wallet artifact {}: {error}",
                    target.display()
                )
            })?;
        } else if *existed && !target.exists() {
            return Err(format!(
                "previous wallet artifact {} is missing from rollback",
                target.display()
            ));
        } else if !*existed {
            match std::fs::remove_file(target) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "remove partially imported wallet artifact {}: {error}",
                        target.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

fn persist_owner_only_atomically(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent directory"))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create {label} directory {}: {error}", parent.display()))?;
    let temporary = path.with_extension(format!("tmp.{:032x}", rand::random::<u128>()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create temporary {label}: {error}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("write {label}: {error}"));
    }
    drop(file);
    #[cfg(target_os = "windows")]
    if path.exists() {
        std::fs::remove_file(path).map_err(|error| format!("replace {label}: {error}"))?;
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("install {label}: {error}"));
    }
    sync_directory(parent, label)
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path, label: &str) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync {label}: {error}"))?;
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn sync_directory(_path: &Path, _label: &str) -> Result<(), String> {
    Ok(())
}

fn normalize_metadata_indices(
    stored_next_index: u32,
    stored_active_index: u32,
    minimum_next_index: u32,
) -> (u32, u32, bool) {
    let active_index = if stored_active_index < MAX_WALLET_ADDRESSES {
        stored_active_index
    } else {
        0
    };
    let required_for_active = active_index + 1;
    let next_index = stored_next_index
        .min(MAX_WALLET_ADDRESSES)
        .max(minimum_next_index.min(MAX_WALLET_ADDRESSES))
        .max(required_for_active);
    let corrected = next_index != stored_next_index || active_index != stored_active_index;
    (next_index, active_index, corrected)
}

impl WalletState {
    fn persist_metadata(&self, next_index: u32, active_index: u32) -> Result<(), String> {
        let path = metadata_path(&self.keystore_path);
        let meta = WalletMetadata {
            next_index,
            active_index,
        };
        let json = serde_json::to_string(&meta)
            .map_err(|error| format!("serialize wallet metadata: {error}"))?;
        let tmp = path.with_extension("meta.tmp");
        std::fs::write(&tmp, json).map_err(|error| format!("write wallet metadata: {error}"))?;
        std::fs::rename(&tmp, &path)
            .map_err(|error| format!("replace wallet metadata: {error}"))?;
        Ok(())
    }

    /// Save lightweight wallet metadata to disk.
    pub fn save_metadata(&self) {
        if let Err(error) = self.persist_metadata(self.next_index, self.active_index) {
            tracing::warn!(%error, "failed to persist wallet metadata");
        }
    }

    /// Load lightweight wallet metadata from disk.
    pub fn load_metadata(&mut self) {
        let path = metadata_path(&self.keystore_path);
        if !path.exists() {
            return;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => return,
        };
        if let Ok(meta) = serde_json::from_str::<WalletMetadata>(&text) {
            let (next_index, active_index, corrected) =
                normalize_metadata_indices(meta.next_index, meta.active_index, self.next_index);
            if meta.next_index > MAX_WALLET_ADDRESSES {
                tracing::warn!(
                    stored = meta.next_index,
                    limit = MAX_WALLET_ADDRESSES,
                    "wallet metadata next_index exceeds address limit; clamping"
                );
            }
            if meta.active_index >= MAX_WALLET_ADDRESSES {
                tracing::warn!(
                    stored = meta.active_index,
                    limit = MAX_WALLET_ADDRESSES,
                    "wallet metadata active_index exceeds address limit; keeping index 0"
                );
            }
            if next_index > self.next_index {
                self.next_index = next_index;
            }
            self.active_index = active_index;
            if corrected {
                self.save_metadata();
            }
            tracing::info!(
                next_index = self.next_index,
                active_index = self.active_index,
                "loaded wallet metadata from disk"
            );
        }
    }

    /// Append only changed receipts, keeping the exported receipt bytes intact.
    pub fn save_receipts(&mut self) -> Result<(), String> {
        let path = receipts_path(&self.keystore_path);
        let reset = self
            .receipts_journal
            .as_ref()
            .is_none_or(|journal| journal.needs_compaction(self.receipts.encoded_budget()));
        if !reset
            && !self.receipts.has_changes()
            && !self
                .receipts_journal
                .as_ref()
                .is_some_and(Journal::has_pending_write)
        {
            self.receipts_dirty = false;
            return Ok(());
        }
        let changes = if reset {
            self.receipts
                .iter()
                .map(|(key, value)| (hex::encode(key), Some(hex::encode(value))))
                .collect()
        } else {
            self.receipts
                .changed_keys()
                .map(|key| (hex::encode(key), self.receipts.get(key).map(hex::encode)))
                .collect()
        };
        let json = serde_json::to_vec(&ReceiptDelta { reset, changes })
            .map_err(|error| format!("serialize wallet receipts: {error}"))?;
        Journal::save(
            &mut self.receipts_journal,
            &path,
            RECEIPTS_MAGIC,
            &json,
            reset,
        )?;
        self.receipts.mark_saved();
        self.receipts_dirty = false;
        Ok(())
    }

    /// Load receipts from disk. Called at startup after create_or_load.
    pub fn load_receipts(&mut self) -> Result<(), String> {
        let path = receipts_path(&self.keystore_path);
        let mut loaded = ReceiptMap::default();
        let mut first = true;
        let journal = Journal::load(&path, RECEIPTS_MAGIC, |bytes| {
            let delta: ReceiptDelta = serde_json::from_slice(bytes)
                .map_err(|e| format!("decode wallet receipt delta: {e}"))?;
            if first && !delta.reset {
                return Err("wallet receipt journal lacks its initial snapshot".into());
            }
            first = false;
            apply_receipt_delta(&mut loaded, delta)
        })?;
        if journal.is_none() && path.exists() {
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("read wallet receipts: {error}"))?;
            let data: BTreeMap<String, String> = serde_json::from_str(&text)
                .map_err(|error| format!("decode wallet receipts: {error}"))?;
            apply_receipt_delta(
                &mut loaded,
                ReceiptDelta {
                    reset: true,
                    changes: data
                        .into_iter()
                        .map(|(key, value)| (key, Some(value)))
                        .collect(),
                },
            )?;
        }
        loaded.mark_saved();
        self.receipts = loaded;
        self.receipts_journal = journal;
        self.receipts_dirty = false;
        tracing::info!(count = self.receipts.len(), "loaded receipts from disk");
        Ok(())
    }

    /// Save wallet transaction history durably.
    pub fn save_history(&mut self) -> Result<(), String> {
        let path = history_path(&self.keystore_path);
        // An upper bound including JSON escaping of legacy free-form labels.
        // Inspecting string lengths does not encode/copy the historical data.
        let budget = self.history.iter().fold(128u64, |sum, entry| {
            sum.saturating_add(1024).saturating_add(
                entry
                    .own_address
                    .as_ref()
                    .map_or(0, |text| (text.len() as u64).saturating_mul(6)),
            )
        });
        let reset = self
            .history_journal
            .as_ref()
            .is_none_or(|journal| journal.needs_compaction(budget));
        let from = if reset {
            0
        } else {
            self.history_dirty_from.unwrap_or(0).min(self.history.len())
        };
        let json = serde_json::to_vec(&HistoryDelta {
            from,
            entries: self.history[from..].to_vec(),
        })
        .map_err(|error| format!("serialize wallet history: {error}"))?;
        Journal::save(
            &mut self.history_journal,
            &path,
            HISTORY_MAGIC,
            &json,
            reset,
        )?;
        self.history_dirty = false;
        self.history_dirty_from = None;
        Ok(())
    }

    /// Load wallet transaction history from disk.
    pub fn load_history(&mut self) -> Result<(), String> {
        let path = history_path(&self.keystore_path);
        let mut loaded = Vec::new();
        let journal = Journal::load(&path, HISTORY_MAGIC, |bytes| {
            let delta: HistoryDelta = serde_json::from_slice(bytes)
                .map_err(|e| format!("decode wallet history delta: {e}"))?;
            if delta.from > loaded.len() {
                return Err("wallet history delta leaves a gap".into());
            }
            loaded.truncate(delta.from);
            loaded.extend(delta.entries);
            Ok(())
        })?;
        if journal.is_none() && path.exists() {
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("read wallet history: {error}"))?;
            loaded = serde_json::from_str(&text)
                .map_err(|error| format!("decode wallet history: {error}"))?;
        }
        self.history = loaded;
        self.history_journal = journal;
        self.history_dirty = false;
        self.history_dirty_from = None;
        tracing::info!(
            count = self.history.len(),
            "loaded wallet history from disk"
        );
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ReceiptDelta {
    reset: bool,
    changes: BTreeMap<String, Option<String>>,
}

fn apply_receipt_delta(receipts: &mut ReceiptMap, delta: ReceiptDelta) -> Result<(), String> {
    if delta.reset {
        *receipts = ReceiptMap::default();
    }
    let mut seen = HashSet::new();
    for (key_hex, value_hex) in delta.changes {
        let key: [u8; 32] = hex::decode(key_hex)
            .map_err(|e| format!("decode wallet receipt key: {e}"))?
            .try_into()
            .map_err(|_| "wallet receipt key is not 32 bytes")?;
        if !seen.insert(key) {
            return Err("duplicate wallet receipt key".into());
        }
        match value_hex {
            Some(value) => {
                receipts.insert(
                    key,
                    hex::decode(value).map_err(|e| format!("decode wallet receipt value: {e}"))?,
                );
            }
            None if !delta.reset => {
                receipts.remove(&key);
            }
            None => return Err("wallet receipt snapshot contains a deletion".into()),
        }
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryDelta {
    from: usize,
    entries: Vec<TxHistoryEntry>,
}

pub(super) fn persist_atomically(
    path: &Path,
    temporary_extension: &str,
    bytes: &[u8],
    label: &str,
) -> Result<(), String> {
    let temporary = path.with_extension(temporary_extension);
    let mut file = std::fs::File::create(&temporary)
        .map_err(|error| format!("create temporary {label}: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {label}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync {label}: {error}"))?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(|error| format!("replace {label}: {error}"))?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| format!("{label} path has no parent directory"))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync {label} directory: {error}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared handle
// ---------------------------------------------------------------------------

/// Thread-safe shared wallet. `None` if wallet is not yet initialized.
pub type SharedWallet = Arc<Mutex<Option<WalletState>>>;

#[cfg(test)]
mod tests {

    #[test]
    fn legacy_history_without_new_markers_remains_readable() {
        let json = r#"{
            "tx_hash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "height":7,
            "direction":"Received",
            "amount_micronoid":50000000,
            "peer_address":null,
            "timestamp":9,
            "own_address":null,
            "own_key_index":0
        }"#;
        let entry: TxHistoryEntry = serde_json::from_str(json).unwrap();
        assert!(!entry.is_coinbase);
        assert!(entry.block_hash.is_none());
    }

    #[test]
    fn corrupt_durable_wallet_artifacts_fail_startup() {
        for extension in ["receipts", "history"] {
            let dir = tempfile::tempdir().unwrap();
            let key_path = dir.path().join("wallet.key");
            WalletState::create_or_load(key_path.clone()).unwrap();
            std::fs::write(key_path.with_extension(extension), b"not-json").unwrap();
            let error = WalletState::create_or_load(key_path.clone())
                .err()
                .expect("corrupt wallet artifact must fail startup");
            assert!(matches!(error, KeystoreError::Artifact(_)));
        }
    }

    #[test]
    fn accepted_tip_reward_is_immediately_selectable_for_its_child() {
        use noid_chain::consensus::params::coinbase_creation_id;

        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let address = wallet.active_address();
        let user = WalletUtxo {
            slot_index: 1,
            value: 40,
            creation_id: 11,
            address,
            key_index: 0,
            confirmed_height: 4,
        };
        let older_reward = WalletUtxo {
            slot_index: 2,
            value: 50,
            creation_id: coinbase_creation_id(3),
            address,
            key_index: 0,
            confirmed_height: 3,
        };
        let tip_reward = WalletUtxo {
            slot_index: 3,
            value: 60,
            creation_id: coinbase_creation_id(7),
            address,
            key_index: 0,
            confirmed_height: 7,
        };
        wallet.utxos.insert(1, user);
        wallet.utxos.insert(2, older_reward);
        wallet.utxos.insert(3, tip_reward);
        wallet.active_snapshot = Some(ActiveWalletSnapshot {
            height: 7,
            tip_hash: [0x22; 32],
            state_root: [0x33; 32],
            log_slots: 8,
            active_slot_count: 3,
            alloc_counter: 11,
        });

        // The height-7 reward exists only after height 7 was accepted, and is
        // therefore selectable while building height 8.
        assert_eq!(wallet.balance(), 150);
        let (selected, change) = wallet
            .select_utxos(150, 0)
            .expect("all accepted rewards are spendable");
        assert_eq!(change, 0);
        let mut slots: Vec<u32> = selected.iter().map(|u| u.slot_index).collect();
        slots.sort_unstable();
        assert_eq!(slots, vec![1, 2, 3]);
    }
    use super::*;

    #[test]
    fn bounded_coin_selection_matches_full_sort_reference() {
        use rand::{Rng, SeedableRng};
        let directory = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(directory.path().join("wallet.key")).unwrap();
        let owner = wallet.active_address();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC015_E1EC7);
        for count in [0, 1, 8, 9, 17, 1000] {
            wallet.utxos.clear();
            wallet.pending_input_slots.clear();
            for i in 0..count {
                let slot = i * 65_537;
                wallet.utxos.insert(
                    slot,
                    WalletUtxo {
                        slot_index: slot,
                        value: rng.gen_range(1..=1000),
                        creation_id: i as u64 + 1,
                        address: owner,
                        key_index: 0,
                        confirmed_height: 1,
                    },
                );
                if i % 5 == 0 {
                    wallet.pending_input_slots.insert(slot);
                }
            }
            for target in [0, 1, 15, 100, 300, 999, 1000, 1500, 6000, 9000, u64::MAX] {
                for fee in [0, 1, 25] {
                    let expected = (|| {
                        let needed = target.checked_add(fee)?;
                        let mut available: Vec<_> = wallet
                            .utxos
                            .values()
                            .filter(|u| !wallet.pending_input_slots.contains(&u.slot_index))
                            .collect();
                        available.sort_by_key(|u| {
                            (std::cmp::Reverse(u.value), u.slot_index >> 16, u.slot_index)
                        });
                        if let Some(exact) = available.iter().find(|u| u.value == needed) {
                            return Some((vec![exact.slot_index], 0));
                        }
                        let mut selected = Vec::new();
                        let mut total = 0u64;
                        for utxo in available.into_iter().take(noid_tx::MAX_PAGED_SPEND_INPUTS) {
                            selected.push(utxo.slot_index);
                            total = total.checked_add(utxo.value)?;
                            if total >= needed {
                                return Some((selected, total - needed));
                            }
                        }
                        None
                    })();
                    let actual = wallet.select_utxos(target, fee).map(|(utxos, change)| {
                        (
                            utxos.into_iter().map(|u| u.slot_index).collect::<Vec<_>>(),
                            change,
                        )
                    });
                    assert_eq!(actual, expected, "count={count} target={target} fee={fee}");
                }
            }
        }
    }

    #[test]
    fn journals_migrate_legacy_files_and_append_only_changed_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(key.clone()).unwrap();
        wallet.record_pending_send([1; 32], 20, [2; 32]).unwrap();
        let old_history = serde_json::to_vec(&wallet.history).unwrap();
        let old_receipts = serde_json::to_vec(&BTreeMap::from([(
            hex::encode([3; 32]),
            hex::encode([4; 1000]),
        )]))
        .unwrap();
        drop(wallet);
        std::fs::write(history_path(&key), &old_history).unwrap();
        std::fs::write(receipts_path(&key), &old_receipts).unwrap();
        let mut wallet = WalletState::create_or_load(key.clone()).unwrap();
        assert_eq!(wallet.get_receipt(&[3; 32]).unwrap(), &vec![4; 1000]);
        wallet.record_pending_send([5; 32], 30, [6; 32]).unwrap();
        wallet.receipts.insert([7; 32], vec![8; 1000]);
        wallet.save_receipts().unwrap();
        assert_eq!(
            std::fs::read(legacy_backup_path(&history_path(&key))).unwrap(),
            old_history
        );
        assert_eq!(
            std::fs::read(legacy_backup_path(&receipts_path(&key))).unwrap(),
            old_receipts
        );
        let receipt_prefix = std::fs::read(receipts_path(&key)).unwrap();
        let history_prefix = std::fs::read(history_path(&key)).unwrap();
        wallet.receipts.insert([7; 32], vec![9; 1000]); // same-size replacement
        wallet.receipts.remove(&[3; 32]);
        wallet.save_receipts().unwrap();
        assert!(std::fs::read(receipts_path(&key))
            .unwrap()
            .starts_with(&receipt_prefix));
        assert!(wallet.confirm_pending_tx(&[5; 32], 50, [0xAA; 32]));
        wallet.save_history().unwrap();
        let history_after = std::fs::read(history_path(&key)).unwrap();
        assert!(history_after.starts_with(&history_prefix));
        assert!(history_after.len() - history_prefix.len() < history_prefix.len());
        drop(wallet);
        let mut wallet = WalletState::create_or_load(key.clone()).unwrap();
        assert!(wallet.get_receipt(&[3; 32]).is_none());
        assert_eq!(wallet.get_receipt(&[7; 32]).unwrap(), &vec![9; 1000]);
        assert_eq!(wallet.history.len(), 2);
        assert_eq!(wallet.history[1].height, 50);
        assert_eq!(wallet.history[1].block_hash, Some([0xAA; 32]));
        wallet.remove_pending_send(&[1; 32]).unwrap();
        wallet.receipts.remove(&[7; 32]);
        wallet.save_receipts().unwrap();
        drop(wallet);
        let wallet = WalletState::create_or_load(key).unwrap();
        assert!(wallet.receipts.is_empty());
        assert_eq!(wallet.history.len(), 1);
        assert_eq!(wallet.history[0].tx_hash, [5; 32]);
    }

    #[test]
    fn journal_compaction_bounds_obsolete_receipt_versions() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(key.clone()).unwrap();
        for version in 0..22u8 {
            wallet.receipts.insert([1; 32], vec![version; 512 * 1024]);
            wallet.save_receipts().unwrap();
        }
        assert!(std::fs::metadata(receipts_path(&key)).unwrap().len() < 20 * 1024 * 1024);
        drop(wallet);
        let wallet = WalletState::create_or_load(key).unwrap();
        assert_eq!(wallet.get_receipt(&[1; 32]).unwrap(), &vec![21; 512 * 1024]);
    }

    #[test]
    fn receipt_journal_matches_map_across_updates_deletions_and_restarts() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(key.clone()).unwrap();
        let mut expected = HashMap::new();
        for round in 0..100u8 {
            let txid = [round % 13; 32];
            if round % 3 == 0 {
                wallet.receipts.remove(&txid);
                expected.remove(&txid);
            } else {
                let bytes = vec![round; usize::from(round) + 1];
                wallet.receipts.insert(txid, bytes.clone());
                expected.insert(txid, bytes);
            }
            wallet.save_receipts().unwrap();
            if round % 7 == 0 {
                drop(wallet);
                wallet = WalletState::create_or_load(key.clone()).unwrap();
            }
            assert_eq!(&*wallet.receipts, &expected);
        }
    }

    #[test]
    fn failed_history_append_keeps_dirty_suffix_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(key.clone()).unwrap();
        wallet.record_pending_send([1; 32], 20, [2; 32]).unwrap();
        wallet.record_pending_send([3; 32], 30, [4; 32]).unwrap();
        wallet.confirm_pending_tx(&[3; 32], 10, [5; 32]);
        let path = history_path(&key);
        let held = directory.path().join("held-history");
        std::fs::rename(&path, &held).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(wallet.save_history().is_err());
        assert!(wallet.history_dirty);
        assert_eq!(wallet.history_dirty_from, Some(1));
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(held, &path).unwrap();
        wallet.save_history().unwrap();
        drop(wallet);
        let wallet = WalletState::create_or_load(key).unwrap();
        assert_eq!(wallet.history[0].height, 0);
        assert_eq!(wallet.history[1].height, 10);
    }

    #[test]
    fn verified_reload_changes_utxo_revision_even_at_the_same_height() {
        let directory = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(directory.path().join("wallet.key")).unwrap();
        let owner = wallet.active_address();
        let before = wallet.utxo_snapshot_revision();
        wallet
            .commit_verified_activation(
                0,
                1,
                0,
                owner.0,
                snapshot(owner.0, Some(10)),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        let first = wallet.utxo_snapshot_revision();
        assert_ne!(first, before);
        wallet
            .commit_verified_activation(
                0,
                1,
                0,
                owner.0,
                snapshot(owner.0, Some(20)),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        assert_ne!(wallet.utxo_snapshot_revision(), first);
    }

    fn snapshot(owner: [u8; 32], amount: Option<u64>) -> VerifiedOwnerSnapshot {
        VerifiedOwnerSnapshot {
            owner,
            height: 19,
            tip_hash: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: 24,
            active_slot_count: u64::from(amount.is_some()),
            alloc_counter: 9,
            utxos: amount
                .map(|amount| noid_chain::storage::VerifiedOwnerUtxo {
                    slot_index: 5,
                    amount,
                    creation_id: 8,
                })
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn metadata_indices_are_bounded_and_keep_active_address_covered() {
        assert_eq!(
            normalize_metadata_indices(u32::MAX, u32::MAX, 50),
            (MAX_WALLET_ADDRESSES, 0, true)
        );
        assert_eq!(
            normalize_metadata_indices(50, MAX_WALLET_ADDRESSES - 1, 50),
            (MAX_WALLET_ADDRESSES, MAX_WALLET_ADDRESSES - 1, true)
        );
        assert_eq!(normalize_metadata_indices(50, 7, 50), (50, 7, false));
    }

    #[test]
    fn active_index_rejects_limit_without_mutating_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let before_next = wallet.next_index;
        let before_active = wallet.active_index;

        assert_eq!(
            wallet.preview_generated_index(MAX_WALLET_ADDRESSES),
            Err("active address index has not been generated")
        );
        assert_eq!(wallet.next_index, before_next);
        assert_eq!(wallet.active_index, before_active);
    }

    #[test]
    fn generated_address_stays_inactive_until_explicitly_selected() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        assert_eq!(wallet.active_index, 0);
        assert_eq!(wallet.next_index, 1);
        assert_eq!(
            wallet.preview_generated_index(1),
            Err("active address index has not been generated")
        );

        let (index, address) = wallet.create_next_inactive_address().unwrap();
        assert_eq!(index, 1);
        assert_ne!(address, wallet.active_address());
        assert_eq!(
            wallet.active_index, 0,
            "generation must not switch accounts"
        );
        assert_eq!(wallet.next_index, 2, "generation must consume one index");

        wallet
            .commit_verified_activation(
                0,
                2,
                index,
                address.0,
                snapshot(address.0, None),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(address, wallet.active_address());
        assert_eq!(wallet.active_index, 1);
        assert_eq!(wallet.next_index, 2);
        assert!(wallet.utxos.is_empty());
        assert_eq!(wallet.active_snapshot.as_ref().unwrap().height, 19);

        let address0 = wallet.preview_generated_index(0).unwrap();
        wallet
            .commit_verified_activation(
                1,
                2,
                0,
                address0.0,
                snapshot(address0.0, None),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(wallet.active_index, 0);
    }

    #[test]
    fn verified_owner_snapshot_replaces_only_the_active_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let owner = wallet.active_address();
        wallet
            .commit_verified_activation(
                0,
                1,
                0,
                owner.0,
                snapshot(owner.0, Some(123)),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(wallet.balance(), 123);
        assert_eq!(wallet.utxos[&5].key_index, 0);
        assert_eq!(wallet.utxos[&5].confirmed_height, 19);
        assert_eq!(
            wallet.active_snapshot.as_ref().unwrap().tip_hash,
            [0x11; 32]
        );

        let wrong_owner = [0xFF; 32];
        assert!(wallet
            .commit_verified_activation(
                0,
                1,
                0,
                wrong_owner,
                snapshot(wrong_owner, None),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap_err()
            .contains("does not match"));
        assert_eq!(wallet.balance(), 123, "failed reload must not erase cache");
    }

    #[test]
    fn failed_switch_lookup_leaves_account_indices_and_cache_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let owner = wallet.active_address();
        wallet
            .commit_verified_activation(
                0,
                1,
                0,
                owner.0,
                snapshot(owner.0, Some(456)),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        wallet.next_index = 2; // index 1 was generated locally before this test's baseline
        let old_snapshot = wallet.active_snapshot.clone();
        let old_utxos = wallet.utxos.clone();

        // The store lookup happens between preview and commit. A lookup error
        // drops this preview and must have no observable wallet effect.
        let _switch_preview = wallet.preview_generated_index(1).unwrap();

        assert_eq!(wallet.active_index, 0);
        assert_eq!(wallet.next_index, 2);
        assert_eq!(wallet.balance(), 456);
        assert_eq!(wallet.active_snapshot, old_snapshot);
        assert_eq!(wallet.utxos.len(), old_utxos.len());
        assert_eq!(wallet.utxos[&5].value, old_utxos[&5].value);
    }

    #[test]
    fn inactive_address_creation_preserves_active_snapshot_and_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let owner = wallet.active_address();
        wallet
            .commit_verified_activation(
                0,
                1,
                0,
                owner.0,
                snapshot(owner.0, Some(789)),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        let old_snapshot = wallet.active_snapshot.clone();
        let old_utxos = wallet.utxos.clone();

        let (created_index, created_address) = wallet.create_next_inactive_address().unwrap();
        assert_eq!(created_index, 1);
        assert_ne!(created_address, owner);

        assert_eq!(wallet.active_index, 0);
        assert_eq!(wallet.next_index, 2);
        assert_eq!(wallet.balance(), 789);
        assert_eq!(wallet.active_snapshot, old_snapshot);
        assert_eq!(wallet.utxos.len(), old_utxos.len());
        assert_eq!(wallet.utxos[&5].value, old_utxos[&5].value);

        let reloaded = WalletState::create_or_load(wallet.keystore_path.clone()).unwrap();
        assert_eq!(reloaded.active_index, 0);
        assert_eq!(reloaded.next_index, 2);
    }

    #[test]
    fn reload_reconciles_pending_sets_with_snapshot_and_mempool() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let owner = wallet.active_address();
        wallet.pending_input_slots.extend([5, 99]);
        wallet.pending_output_slots.extend([7, 8]);

        wallet
            .commit_verified_activation(
                0,
                1,
                0,
                owner.0,
                snapshot(owner.0, Some(100)),
                &HashSet::from([5, 99]),
                &HashSet::from([7]),
            )
            .unwrap();

        assert_eq!(wallet.pending_input_slots, HashSet::from([5]));
        assert_eq!(wallet.pending_output_slots, HashSet::from([7]));

        wallet
            .commit_verified_activation(
                0,
                1,
                0,
                owner.0,
                snapshot(owner.0, Some(100)),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        assert!(!wallet.has_pending_activity());
    }

    #[test]
    fn pending_activity_blocks_account_change_until_reload_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let owner = wallet.active_address();
        wallet.next_index = 2;
        wallet.pending_input_slots.insert(5);

        assert!(wallet
            .preview_generated_index(1)
            .unwrap_err()
            .contains("pending"));
        let (created_index, _) = wallet.create_next_inactive_address().unwrap();
        assert_eq!(created_index, 2);
        assert_eq!(wallet.active_index, 0);
        assert!(wallet.preview_generated_index(0).is_ok());

        wallet
            .commit_verified_activation(
                0,
                3,
                0,
                owner.0,
                snapshot(owner.0, Some(100)),
                &HashSet::new(),
                &HashSet::new(),
            )
            .unwrap();
        assert!(wallet.preview_generated_index(1).is_ok());
    }

    #[test]
    fn pending_send_is_tagged_with_its_source_account() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        let expected_address = wallet.active_address().to_bech32();
        wallet.record_pending_send([3; 32], 77, [4; 32]).unwrap();

        let entry = wallet.history.last().unwrap();
        assert_eq!(entry.own_key_index, Some(0));
        assert_eq!(
            entry.own_address.as_deref(),
            Some(expected_address.as_str())
        );
    }

    #[test]
    fn generated_master_secret_round_trip_resets_local_wallet_records() {
        let source_dir = tempfile::tempdir().unwrap();
        let source_key = source_dir.path().join("wallet.key");
        let source = WalletState::create_or_load(source_key.clone()).unwrap();
        let expected_addresses = [
            source.address_at(0),
            source.address_at(4),
            source.address_at(8),
        ];
        let master_secret = export_generated_master_secret(&source_key).unwrap();
        assert_eq!(master_secret.len(), 64);
        assert!(master_secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!master_secret.bytes().any(|byte| byte.is_ascii_uppercase()));
        drop(source);

        let target_dir = tempfile::tempdir().unwrap();
        let target_key = target_dir.path().join("wallet.key");
        let mut target = WalletState::create_or_load(target_key.clone()).unwrap();
        let previous_address = target.address_at(0);
        target.next_index = 9;
        target.active_index = 4;
        target.history.push(TxHistoryEntry {
            tx_hash: [0x21; 32],
            block_hash: None,
            height: 3,
            direction: TxDirection::Sent,
            is_coinbase: false,
            amount_micronoid: 9,
            peer_address: None,
            timestamp: 7,
            own_address: Some(previous_address.to_bech32()),
            own_key_index: Some(0),
        });
        target.receipts.insert([0x31; 32], vec![0x41; 16]);
        target.save_metadata();
        target.save_history().unwrap();
        target.save_receipts().unwrap();
        // Reset/import must retire the previous wallet's migration backups as
        // well as its current artifacts, otherwise the next migration could
        // encounter unrelated stale backups.
        let old_history_backup = legacy_backup_path(&history_path(&target_key));
        let old_receipts_backup = legacy_backup_path(&receipts_path(&target_key));
        std::fs::write(&old_history_backup, b"[]").unwrap();
        std::fs::write(&old_receipts_backup, b"{}").unwrap();
        drop(target);

        let pasted = Zeroizing::new(format!(
            "{}\n{}",
            &master_secret[..32],
            &master_secret[32..]
        ));
        import_generated_master_secret(&target_key, &pasted).unwrap();
        assert!(!old_history_backup.exists());
        assert!(!old_receipts_backup.exists());

        let imported = WalletState::create_or_load(target_key).unwrap();
        assert_ne!(imported.address_at(0), previous_address);
        assert_eq!(imported.address_at(0), expected_addresses[0]);
        assert_eq!(imported.address_at(4), expected_addresses[1]);
        assert_eq!(imported.address_at(8), expected_addresses[2]);
        assert_eq!(imported.next_index, 1);
        assert_eq!(imported.active_index, 0);
        assert!(imported.history.is_empty());
        assert!(imported.receipts.is_empty());
        assert_eq!(
            std::fs::read_dir(target_dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".wallet-import"))
                .count(),
            0
        );
    }

    #[test]
    fn rejected_generated_master_secret_does_not_mutate_wallet() {
        let target_dir = tempfile::tempdir().unwrap();
        let target_key = target_dir.path().join("wallet.key");
        let target = WalletState::create_or_load(target_key.clone()).unwrap();
        target.save_metadata();
        let key_before = std::fs::read(&target_key).unwrap();
        let metadata_before = std::fs::read(metadata_path(&target_key)).unwrap();
        drop(target);

        assert!(import_generated_master_secret(&target_key, &"g".repeat(64)).is_err());
        assert_eq!(std::fs::read(&target_key).unwrap(), key_before);
        assert_eq!(
            std::fs::read(metadata_path(&target_key)).unwrap(),
            metadata_before
        );
        assert_eq!(
            std::fs::read_dir(target_dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".wallet-import"))
                .count(),
            0
        );
    }

    #[test]
    fn discovered_address_prefix_does_not_change_active_owner() {
        let directory = tempfile::tempdir().unwrap();
        let mut wallet = WalletState::create_or_load(directory.path().join("wallet.key")).unwrap();
        let active = wallet.active_address();

        wallet.commit_discovered_next_index(0, 1, 4).unwrap();

        assert_eq!(wallet.active_index, 0);
        assert_eq!(wallet.active_address(), active);
        assert_eq!(wallet.next_index, 4);
        assert!(wallet.preview_generated_index(3).is_ok());
        assert!(wallet.preview_generated_index(4).is_err());
    }

    #[test]
    fn wallet_sidecars_never_persist_master_or_derived_spend_secret() {
        use zeroize::Zeroize;

        fn contains(haystack: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
        }

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(key_path.clone()).unwrap();
        let spend_secret = wallet.spend_secret_for(0);
        let mut spend_bytes = spend_secret.with_exposed_prover_fields(|fields| {
            let mut bytes = [0u8; 32];
            bytes[..16].copy_from_slice(&fields[0].0.to_le_bytes());
            bytes[16..].copy_from_slice(&fields[1].0.to_le_bytes());
            bytes
        });

        wallet.next_index = 7;
        wallet.history.push(TxHistoryEntry {
            tx_hash: [0x11; 32],
            block_hash: None,
            height: 9,
            direction: TxDirection::Sent,
            is_coinbase: false,
            amount_micronoid: 77,
            peer_address: Some([0x22; 32]),
            timestamp: 123,
            own_address: Some(wallet.active_address().to_bech32()),
            own_key_index: Some(0),
        });
        wallet.receipts.insert([0x33; 32], vec![0x44; 96]);
        wallet.save_metadata();
        wallet.save_history().unwrap();
        wallet.save_receipts().unwrap();

        let mut key_file = std::fs::read(&key_path).unwrap();
        assert_eq!(key_file.len(), 48);
        let mut master_bytes = [0u8; 32];
        master_bytes.copy_from_slice(&key_file[16..]);
        let master_hex = hex::encode(master_bytes);
        let spend_hex = hex::encode(spend_bytes);

        for path in [
            metadata_path(&key_path),
            history_path(&key_path),
            receipts_path(&key_path),
        ] {
            let mut persisted = std::fs::read(&path).unwrap();
            assert!(
                !contains(&persisted, &master_bytes),
                "master secret in {path:?}"
            );
            assert!(
                !contains(&persisted, &spend_bytes),
                "spend secret in {path:?}"
            );
            assert!(
                !contains(&persisted, master_hex.as_bytes()),
                "hex master secret in {path:?}"
            );
            assert!(
                !contains(&persisted, spend_hex.as_bytes()),
                "hex spend secret in {path:?}"
            );
            persisted.zeroize();
        }

        key_file.zeroize();
        master_bytes.zeroize();
        spend_bytes.zeroize();
    }
}
