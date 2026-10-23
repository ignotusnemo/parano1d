// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Durable public openings and receipts. These files never contain wallet
//! keys. Replacement is atomic, and every reload is bounded and revalidated.

use noid_block::contract_receipt::{ObjectTransitionReceipt, MAX_RECEIPT_BYTES};
use noid_tx::experimental_object::{ObjectOpening, OPENING_BYTES};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

mod activity;
mod related;

pub(super) fn receipt_page(
    key: &Path,
    opening: &ObjectOpening,
    after: Option<&str>,
    limit: usize,
) -> Result<noid_rpc::wallet_ops::WalletObjectReceiptPage, String> {
    activity::page(key, opening, after, limit)
}

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
// Local storage only: exported receipts keep their original self-contained
// consensus-proof framing. Calls in one block share these exact proof bytes.
const RECEIPT_REFERENCE_MAGIC: &[u8; 8] = b"NOIDORF1";
const RECEIPT_REFERENCE_HEADER: usize = RECEIPT_REFERENCE_MAGIC.len() + 32;
const TERMINAL_LIMIT: usize =
    noid_chain::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES;

fn directory(key_path: &Path) -> Result<PathBuf, String> {
    Ok(key_path
        .parent()
        .ok_or("wallet directory missing")?
        .join("objects"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("object artifact directory missing")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let (temporary, mut file) = loop {
        let temporary = path.with_extension(format!(
            "{}.{}.partial",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    };
    let result = (|| {
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("object artifact file bound".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("object artifact grew beyond bound".into());
    }
    Ok(bytes)
}

pub(super) fn save_opening(key_path: &Path, opening: &ObjectOpening) -> Result<(), String> {
    let path = directory(key_path)?.join(format!("{}.opening", hex::encode(opening.root().0)));
    let bytes = opening.to_bytes().map_err(|e| e.to_string())?;
    if !read_bounded(&path, OPENING_BYTES).is_ok_and(|existing| existing == bytes) {
        write_atomic(&path, &bytes)?;
    }
    related::remember(key_path, opening)
}

pub(super) fn related_openings(
    key_path: &Path,
    opening: &ObjectOpening,
    after: Option<[u8; 32]>,
    limit: usize,
) -> Result<noid_rpc::wallet_ops::WalletObjectOpeningPage, String> {
    let (openings, next_root) = related::page(key_path, opening, after, limit)?;
    Ok(noid_rpc::wallet_ops::WalletObjectOpeningPage {
        openings,
        next_root,
    })
}

pub(super) fn load_opening(key_path: &Path, root: [u8; 32]) -> Result<ObjectOpening, String> {
    let path = directory(key_path)?.join(format!("{}.opening", hex::encode(root)));
    let opening = ObjectOpening::from_bytes(&read_bounded(&path, OPENING_BYTES)?)
        .map_err(|e| e.to_string())?;
    if opening.root().0 != root {
        return Err("saved opening root mismatch".into());
    }
    Ok(opening)
}

pub(super) fn save_receipt(key_path: &Path, txid: [u8; 32], bytes: &[u8]) -> Result<(), String> {
    let receipt = ObjectTransitionReceipt::from_bytes(bytes)?;
    if noid_tx::hash_paged_spend(std::slice::from_ref(&receipt.page))
        .map_err(|e| e.to_string())?
        .0
        != txid
    {
        return Err("object receipt transaction mismatch".into());
    }
    let directory = directory(key_path)?;
    let digest = blake3::hash(&receipt.terminal);
    let terminal_path = directory
        .join("terminals")
        .join(format!("{}.terminal", digest.to_hex()));
    // Check an existing object as well: a valid replacement receipt can heal
    // local corruption while its block still belongs to the serving window.
    if !read_bounded(&terminal_path, TERMINAL_LIMIT)
        .is_ok_and(|existing| existing == receipt.terminal)
    {
        write_atomic(&terminal_path, &receipt.terminal)?;
    }
    // to_bytes/from_bytes place the terminal at the end, with its exact length
    // immediately before it. This preserves both direct and descendant forms.
    let prefix = &bytes[..bytes.len() - receipt.terminal.len()];
    let mut reference = Vec::with_capacity(RECEIPT_REFERENCE_HEADER + prefix.len());
    reference.extend_from_slice(RECEIPT_REFERENCE_MAGIC);
    reference.extend_from_slice(digest.as_bytes());
    reference.extend_from_slice(prefix);
    // Proof first, reference last. The final directory sync also persists a
    // newly created terminals/ directory alongside the receipt reference.
    write_atomic(
        &directory.join(format!("{}.receipt", hex::encode(txid))),
        &reference,
    )?;
    activity::remember(key_path, &receipt)
}

pub(super) fn load_receipt(key_path: &Path, txid: [u8; 32]) -> Result<Vec<u8>, String> {
    let stored = read_bounded(
        &directory(key_path)?.join(format!("{}.receipt", hex::encode(txid))),
        MAX_RECEIPT_BYTES,
    )?;
    let bytes = if stored.starts_with(RECEIPT_REFERENCE_MAGIC) {
        if stored.len() < RECEIPT_REFERENCE_HEADER + noid_block::contract_receipt::FIXED_BYTES
            || stored.len() > RECEIPT_REFERENCE_HEADER + MAX_RECEIPT_BYTES - TERMINAL_LIMIT
        {
            return Err("saved object receipt reference bound".into());
        }
        let digest = &stored[8..RECEIPT_REFERENCE_HEADER];
        let prefix = &stored[RECEIPT_REFERENCE_HEADER..];
        let length = u32::from_le_bytes(prefix[prefix.len() - 4..].try_into().unwrap()) as usize;
        if length == 0 || length > TERMINAL_LIMIT || prefix.len() + length > MAX_RECEIPT_BYTES {
            return Err("saved object receipt terminal bound".into());
        }
        let terminal_path = directory(key_path)?
            .join("terminals")
            .join(format!("{}.terminal", hex::encode(digest)));
        let terminal = read_bounded(&terminal_path, length)?;
        if terminal.len() != length || blake3::hash(&terminal).as_bytes() != digest {
            return Err("saved object receipt terminal mismatch".into());
        }
        let mut bytes = Vec::with_capacity(prefix.len() + length);
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&terminal);
        bytes
    } else {
        // Read existing full receipts unchanged. A later save may migrate one
        // atomically; merely opening a wallet never rewrites its backups.
        stored
    };
    let receipt = ObjectTransitionReceipt::from_bytes(&bytes)?;
    if noid_tx::hash_paged_spend(std::slice::from_ref(&receipt.page))
        .map_err(|e| e.to_string())?
        .0
        != txid
    {
        return Err("saved object receipt transaction mismatch".into());
    }
    Ok(bytes)
}

/// Recover the complete bounded serving window after a suffix is committed.
/// Earlier intermediate blocks can lack an individual terminal until its last
/// block arrives; replaying only that last body would lose their receipts.
pub(super) fn retain_from_chain(
    key_path: &Path,
    chain: &noid_chain::storage::MdbxChainContext,
) -> Result<usize, String> {
    let tip = chain.tip_height();
    if !noid_chain::consensus::params::v2_active(tip) || !directory(key_path)?.is_dir() {
        return Ok(0);
    }
    let first = tip
        .saturating_sub(
            noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH.saturating_sub(1),
        )
        .max(noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.unwrap());
    let mut retained = 0;
    for height in first..=tip {
        if let Some(bytes) = chain
            .store
            .get_recent_canonical_block(height)
            .map_err(|e| e.to_string())?
        {
            let block = noid_chain::Block::from_bytes(&bytes)
                .map_err(|e| format!("retained contract block: {e:?}"))?;
            retained += retain_from_block(key_path, &chain.store, &block)?;
        }
    }
    Ok(retained)
}

/// Capture receipts for every locally retained opening, including calls made
/// by its other authority. Public artifacts survive account switches and can
/// be recovered from the bounded body window after an interrupted wallet fsync.
pub(super) fn retain_from_block(
    key_path: &Path,
    store: &noid_chain::storage::MdbxStore,
    block: &noid_chain::Block,
) -> Result<usize, String> {
    if !noid_chain::consensus::params::v2_active(block.header.height)
        || !directory(key_path)?.is_dir()
    {
        return Ok(0);
    }
    let stream = noid_chain::block::native_assets::validate_scheduled_block_page_stream(
        &block.transactions,
        block.header.height,
    )
    .map_err(|e| e.to_string())?;
    let mut retained = 0;
    for (group_index, group) in stream.groups().enumerate() {
        let body = &block.transactions[group.body_start].body;
        if body.validity_bitmap & noid_tx::PAGED_SPEND_CONTRACT_BIT == 0 {
            break;
        }
        let root = group.authority().0;
        if !directory(key_path)?
            .join(format!("{}.opening", hex::encode(root)))
            .exists()
        {
            continue;
        }
        let opening = load_opening(key_path, root)?;
        let txid = group.logical_txid().0;
        if let Some(receipt) = load_receipt(key_path, txid)
            .ok()
            .and_then(|bytes| ObjectTransitionReceipt::from_bytes(&bytes).ok())
        {
            if receipt.header == block.header && receipt.opening == opening {
                // Heal an interrupted write between the durable receipt and its
                // optional activity index even after migration has completed.
                activity::remember(key_path, &receipt)?;
                continue;
            }
        }
        let Some(receipt) =
            noid_rpc::object_receipts::from_store(store, block, group_index, opening)?
        else {
            continue;
        };
        let checked = receipt
            .opening
            .check_call(&receipt.page, receipt.header.height)
            .map_err(|e| e.to_string())?;
        if !checked.terminal {
            save_opening(key_path, &receipt.opening.successor(checked.next))?;
        }
        save_receipt(key_path, txid, &receipt.to_bytes()?)?;
        retained += 1;
    }
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;

    // Local framing/inclusion fixtures only; the dummy terminal is not proof
    // authority. Live exported-receipt verification is tested by real nodes.
    fn receipt_fixtures() -> Vec<ObjectTransitionReceipt> {
        use noid_tx::{Transaction, TxBody, TxInput, TxOutput};
        let height = noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.unwrap();
        let owner = Address([7; 32]);
        let opening = noid_tx::experimental_object::applications::timelocked_vault(owner, 0, 5);
        let mut outputs = [TxOutput::dummy(); noid_tx::TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 0,
            amount: 16_000_000,
            owner,
        };
        let mut transactions = vec![Transaction::new(TxBody {
            epoch_anchor: [0; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); noid_tx::TX_INPUTS],
            outputs,
            validity_bitmap: noid_tx::output_bitmap_bit(0),
            is_coinbase: true,
        })];
        for index in 0..2u32 {
            let call = opening
                .build_call(
                    TxInput {
                        slot_index: index + 1,
                        amount: 1001,
                        creation_id: u64::from(index) + 1,
                    },
                    index + 100,
                    1,
                    [0; 32],
                    height,
                    true,
                )
                .unwrap();
            transactions.push(Transaction::new(call.body));
        }
        let epoch = noid_chain::consensus::genesis_header();
        let mut header = epoch;
        header.height = height;
        header.difficulty_target = [0xff; 32];
        header.tx_root = noid_chain::block::compute_tx_root(&transactions);
        let block = noid_chain::Block {
            header,
            transactions,
        };
        (0..2)
            .map(|index| {
                ObjectTransitionReceipt::from_block(
                    &block,
                    index,
                    opening.clone(),
                    epoch,
                    vec![42; 8192],
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn activity_migrates_old_receipts_paginates_and_browses_without_terminals() {
        let temporary = tempfile::tempdir().unwrap();
        let key = temporary.path().join("wallet.key");
        let root = directory(&key).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let receipts = receipt_fixtures();
        // Simulate an existing wallet before the compact discovery index.
        for receipt in &receipts {
            std::fs::write(
                root.join(format!("{}.receipt", hex::encode(receipt_id(receipt)))),
                receipt.to_bytes().unwrap(),
            )
            .unwrap();
        }
        let first = receipt_page(&key, &receipts[0].opening, None, 1).unwrap();
        assert_eq!(first.receipts.len(), 1);
        assert!(first.next_cursor.is_some());
        // Index has migrated. Listing still works with no receipt bodies at all;
        // exporting a receipt continues to require the actual saved proof.
        for receipt in &receipts {
            std::fs::remove_file(
                root.join(format!("{}.receipt", hex::encode(receipt_id(receipt)))),
            )
            .unwrap();
        }
        let second =
            receipt_page(&key, &receipts[0].opening, first.next_cursor.as_deref(), 1).unwrap();
        assert_eq!(second.receipts.len(), 1);
        assert!(second.next_cursor.is_none());
        let id = |record: &noid_rpc::wallet_ops::WalletObjectReceiptRecord| {
            noid_tx::hash_paged_spend(std::slice::from_ref(&record.page)).unwrap()
        };
        assert_ne!(id(&first.receipts[0]), id(&second.receipts[0]));
        // A different saved counter state belongs to the same immutable family.
        let sibling = receipts[0].opening.successor(
            noid_tx::experimental_object::integer_program::pack_state([1, 2]),
        );
        assert_eq!(
            receipt_page(&key, &sibling, None, 64)
                .unwrap()
                .receipts
                .len(),
            2
        );
        let mut unrelated = sibling;
        unrelated.deadline += 1;
        assert!(receipt_page(&key, &unrelated, None, 64)
            .unwrap()
            .receipts
            .is_empty());
        assert!(receipt_page(&key, &receipts[0].opening, Some("../../outside"), 1).is_err());
        assert!(receipt_page(&key, &receipts[0].opening, None, 65).is_err());
        // Re-import heals missing artifacts and is idempotent.
        for _ in 0..2 {
            save_receipt(
                &key,
                receipt_id(&receipts[0]),
                &receipts[0].to_bytes().unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            receipt_page(&key, &receipts[0].opening, None, 64)
                .unwrap()
                .receipts
                .len(),
            2
        );
    }

    #[test]
    fn activity_rejects_metadata_not_bound_to_the_retained_header() {
        let temporary = tempfile::tempdir().unwrap();
        let key = temporary.path().join("wallet.key");
        let receipt = receipt_fixtures().remove(0);
        save_receipt(&key, receipt_id(&receipt), &receipt.to_bytes().unwrap()).unwrap();
        receipt_page(&key, &receipt.opening, None, 64).unwrap();
        let family = hex::encode(receipt.opening.successor(Default::default()).root().0);
        let path = directory(&key)
            .unwrap()
            .join("activity-v1")
            .join(family)
            .join(format!(
                "{:016x}-{}",
                receipt.header.height,
                hex::encode(receipt_id(&receipt))
            ));
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["path"][0][0] = serde_json::json!(255);
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(receipt_page(&key, &receipt.opening, None, 64)
            .err()
            .unwrap()
            .contains("inclusion mismatch"));
        save_receipt(&key, receipt_id(&receipt), &receipt.to_bytes().unwrap()).unwrap();
        assert_eq!(
            receipt_page(&key, &receipt.opening, None, 64)
                .unwrap()
                .receipts
                .len(),
            1
        );
    }

    fn receipt_id(receipt: &ObjectTransitionReceipt) -> [u8; 32] {
        noid_tx::hash_paged_spend(std::slice::from_ref(&receipt.page))
            .unwrap()
            .0
    }

    #[test]
    fn same_block_receipts_share_proof_bytes_and_export_identical_wire() {
        let temporary = tempfile::tempdir().unwrap();
        let key = temporary.path().join("wallet.key");
        let receipts = receipt_fixtures();
        let mut wire_total = 0;
        let mut stored_total = 0;
        for receipt in &receipts {
            let txid = receipt_id(receipt);
            let wire = receipt.to_bytes().unwrap();
            save_receipt(&key, txid, &wire).unwrap();
            assert_eq!(load_receipt(&key, txid).unwrap(), wire);
            let path = directory(&key)
                .unwrap()
                .join(format!("{}.receipt", hex::encode(txid)));
            let stored = std::fs::read(path).unwrap();
            assert!(stored.starts_with(RECEIPT_REFERENCE_MAGIC));
            assert_eq!(
                stored.len(),
                RECEIPT_REFERENCE_HEADER + wire.len() - receipt.terminal.len()
            );
            stored_total += stored.len();
            wire_total += wire.len();
        }
        let proofs = directory(&key).unwrap().join("terminals");
        assert_eq!(std::fs::read_dir(proofs).unwrap().count(), 1);
        stored_total += receipts[0].terminal.len();
        assert!(stored_total < wire_total);
        let first = &receipts[0];
        let second = &receipts[1];
        let root = directory(&key).unwrap();
        std::fs::copy(
            root.join(format!("{}.receipt", hex::encode(receipt_id(first)))),
            root.join(format!("{}.receipt", hex::encode(receipt_id(second)))),
        )
        .unwrap();
        assert!(load_receipt(&key, receipt_id(second))
            .unwrap_err()
            .contains("transaction mismatch"));
    }

    #[test]
    fn proof_references_fail_closed_and_valid_receipts_heal_local_corruption() {
        let temporary = tempfile::tempdir().unwrap();
        let key = temporary.path().join("wallet.key");
        let receipt = receipt_fixtures().remove(0);
        let txid = receipt_id(&receipt);
        let wire = receipt.to_bytes().unwrap();
        save_receipt(&key, txid, &wire).unwrap();
        let root = directory(&key).unwrap();
        let proof = root.join("terminals").join(format!(
            "{}.terminal",
            blake3::hash(&receipt.terminal).to_hex()
        ));
        let mut corrupt = receipt.terminal.clone();
        corrupt[0] ^= 1;
        std::fs::write(&proof, corrupt).unwrap();
        assert!(load_receipt(&key, txid)
            .unwrap_err()
            .contains("terminal mismatch"));
        save_receipt(&key, txid, &wire).unwrap();
        assert_eq!(load_receipt(&key, txid).unwrap(), wire);
        std::fs::remove_file(proof).unwrap();
        assert!(load_receipt(&key, txid).is_err());
        save_receipt(&key, txid, &wire).unwrap();
        let path = root.join(format!("{}.receipt", hex::encode(txid)));
        let mut reference = std::fs::read(&path).unwrap();
        let len = reference.len();
        reference[len - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(path, reference).unwrap();
        assert!(load_receipt(&key, txid)
            .unwrap_err()
            .contains("terminal bound"));
    }

    #[test]
    fn full_receipts_and_descendant_receipts_survive_local_storage_migration() {
        let temporary = tempfile::tempdir().unwrap();
        let key = temporary.path().join("wallet.key");
        let mut receipt = receipt_fixtures().remove(0);
        let mut child = receipt.header;
        child.height += 1;
        child.prev_block_hash = noid_chain::block_id(&receipt.header);
        receipt.descendants.push(child);
        let wire = receipt.to_bytes().unwrap();
        let txid = receipt_id(&receipt);
        let root = directory(&key).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("{}.receipt", hex::encode(txid)));
        std::fs::write(&path, &wire).unwrap();
        assert_eq!(load_receipt(&key, txid).unwrap(), wire);
        assert_eq!(std::fs::read(&path).unwrap(), wire); // Reads do not migrate.
        save_receipt(&key, txid, &wire).unwrap();
        assert!(std::fs::read(path)
            .unwrap()
            .starts_with(RECEIPT_REFERENCE_MAGIC));
        assert_eq!(load_receipt(&key, txid).unwrap(), wire);
    }

    #[test]
    fn durable_openings_are_bounded_and_bound_to_their_filename() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("wallet.key");
        let opening =
            noid_tx::experimental_object::applications::timelocked_vault(Address([7; 32]), 20, 3);
        save_opening(&key, &opening).unwrap();
        assert_eq!(load_opening(&key, opening.root().0).unwrap(), opening);
        let path = directory(&key)
            .unwrap()
            .join(format!("{}.opening", hex::encode(opening.root().0)));
        let mut other = opening.clone();
        other.deadline += 1;
        std::fs::write(&path, other.to_bytes().unwrap()).unwrap();
        assert!(load_opening(&key, opening.root().0)
            .unwrap_err()
            .contains("root mismatch"));
        std::fs::write(&path, vec![0; OPENING_BYTES + 1]).unwrap();
        assert!(load_opening(&key, opening.root().0)
            .unwrap_err()
            .contains("bound"));
        save_opening(&key, &opening).unwrap();
        assert_eq!(load_opening(&key, opening.root().0).unwrap(), opening);
        assert!(std::fs::read_dir(directory(&key).unwrap())
            .unwrap()
            .all(|entry| !entry.unwrap().path().to_string_lossy().ends_with("partial")));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_reload_rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, [0; 3]).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_bounded(&link, 3).is_err());
    }
}
