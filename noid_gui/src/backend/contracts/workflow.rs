// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::contracts::{
    validate_name, Confirmation, ContractFile, OpenedFile, ReceiptKind, RetainedCalls, SharedProof,
    VerifiedReceipt, ACTIVITY_FILE_LIMIT, ACTIVITY_LIMIT, CONTRACT_FILE_LIMIT,
};

#[cfg(test)]
mod live;

impl Backend {
    pub(super) async fn prepare_contract_funding(
        &self,
        info: Info,
        amount: u64,
        fee: u64,
        sender: String,
        creation: Option<Creation>,
    ) -> Result<Outcome, String> {
        let active: Value = self.contract_rpc("walletActiveAddress", json!([])).await?;
        if active["address"] != sender {
            return Err("Active address changed. Review the transaction again.".into());
        }
        let quote: Value = self
            .contract_rpc("walletPlanSend", json!([info.address, amount, fee]))
            .await?;
        let fee = quote["fee_micronoid"]
            .as_u64()
            .ok_or("Invalid funding quote.")?;
        Ok(Outcome::FundingReview {
            info,
            amount,
            fee,
            sender,
            creation,
        })
    }

    pub(super) async fn remember_contract_metadata(
        &self,
        info: &Info,
        name: &str,
        kind: Option<crate::contracts::Kind>,
        source: Source,
    ) -> Result<(), String> {
        validate_name(name)?;
        let mut library = self.remember_contract(info, None, false).await?;
        let entry = library
            .iter_mut()
            .find(|entry| entry.info.family_key() == info.family_key())
            .ok_or("Saved contract list changed. Reload it.")?;
        if !name.is_empty() && (source != Source::Imported || entry.name.is_empty()) {
            entry.name = name.to_owned();
        }
        // File-supplied template names are never trusted as a description of rules.
        if kind.is_some() {
            entry.kind = kind;
        }
        if entry.source == Source::Existing {
            entry.source = source;
        }
        self.save_contract_library(&library).await
    }

    fn activity_path(&self, info: &Info) -> Result<PathBuf, String> {
        Ok(self
            .config_snapshot()?
            .data_dir
            .join("contract-activity")
            .join(format!("{}.json", info.family_key())))
    }

    fn proof_path(&self, txid: &str) -> Result<PathBuf, String> {
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid operation ID.".into());
        }
        Ok(self
            .config_snapshot()?
            .data_dir
            .join("contract-activity")
            .join("receipts")
            .join(format!("{txid}.receipt")))
    }

    fn operation_proof_path(&self, operation: &Operation) -> Result<PathBuf, String> {
        let mut path = self.proof_path(&operation.txid)?;
        if let Some(confirmation) = &operation.confirmation {
            let hash = &confirmation.block_hash;
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Invalid block hash.".into());
            }
            path.set_file_name(format!("{}-{hash}.receipt", operation.txid));
        }
        Ok(path)
    }

    async fn read_activity(&self, info: &Info) -> Result<Vec<Operation>, String> {
        let path = self.activity_path(info)?;
        if !tokio::fs::try_exists(&path)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(Vec::new());
        }
        let activity: Vec<Operation> =
            serde_json::from_slice(&read_file(&path, ACTIVITY_FILE_LIMIT).await?)
                .map_err(|e| e.to_string())?;
        if activity.len() > ACTIVITY_LIMIT || activity.iter().any(|op| !op.valid()) {
            return Err("Invalid local contract activity.".into());
        }
        Ok(activity)
    }

    async fn persist_activity(&self, info: &Info, activity: &[Operation]) -> Result<(), String> {
        let path = self.activity_path(info)?;
        let bytes = serde_json::to_vec(activity).map_err(|e| e.to_string())?;
        if bytes.len() > ACTIVITY_FILE_LIMIT || activity.len() > ACTIVITY_LIMIT {
            return Err("Contract activity exceeds its limit.".into());
        }
        persist_artifact(path, bytes).await
    }

    pub(super) async fn remember_operation(
        &self,
        info: &Info,
        operation: Operation,
    ) -> Result<(), String> {
        if !operation.valid() {
            return Err("Invalid contract operation.".into());
        }
        let mut activity = self.read_activity(info).await?;
        merge_operation(&mut activity, operation)?;
        self.persist_activity(info, &activity).await
    }

    async fn operation_proof(&self, operation: &Operation) -> Result<String, String> {
        let path = self.operation_proof_path(operation)?;
        if tokio::fs::try_exists(&path)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(hex::encode(read_file(&path, RECEIPT_LIMIT).await?));
        }
        let encoded: String = if operation.kind == OperationKind::Funding {
            self.contract_rpc("walletExportReceipt", json!([operation.txid]))
                .await?
        } else {
            self.contract_rpc(
                "exportObjectReceipt",
                json!([operation.opening_hex, operation.txid]),
            )
            .await?
        };
        let bytes = hex::decode(&encoded).map_err(|e| e.to_string())?;
        if bytes.len() > RECEIPT_LIMIT {
            return Err("Receipt exceeds its file limit.".into());
        }
        persist_artifact(path, bytes).await?;
        Ok(encoded)
    }

    pub(super) async fn contract_activity(&self, info: &Info) -> Result<Vec<Operation>, String> {
        let mut activity = self.read_activity(info).await?;
        let mut retained = std::collections::BTreeMap::new();
        let mut cursor: Option<String> = None;
        // Metadata includes calls retained while following this contract, whoever
        // signed them. Full recursive proofs are read only when sharing/exporting.
        for _ in 0..ACTIVITY_LIMIT.div_ceil(64) {
            let page: RetainedCalls = self
                .contract_rpc(
                    "walletListObjectReceipts",
                    json!([info.opening_hex, cursor, 64]),
                )
                .await?;
            let anchor: Option<String> = self
                .contract_rpc("getBlockHash", json!([page.height]))
                .await?;
            if anchor.as_deref() != Some(&page.tip_hash) {
                return Err(
                    "The chain changed while reading contract activity. Refresh again.".into(),
                );
            }
            for entry in page.entries.into_iter().rev() {
                validate_call(&entry.call)?;
                if entry.call.original.family_key() != info.family_key() {
                    return Err("Saved receipt belongs to another contract.".into());
                }
                let operation =
                    call_operation(&entry.call, entry.block_hash.clone(), entry.canonical);
                if entry.canonical {
                    retained.insert(operation.txid.clone(), entry.block_hash);
                }
                merge_operation(&mut activity, operation)?;
            }
            if page.next_cursor.is_none() {
                break;
            }
            if page.next_cursor == cursor {
                return Err("Invalid contract activity cursor.".into());
            }
            cursor = page.next_cursor;
        }
        // Recover recent funding receipts, including a submission followed by a
        // GUI crash before its journal write. Existing wallet proofs remain durable.
        let receipts: RpcWalletReceiptsPage =
            self.contract_rpc("walletReceipts", json!([1, 50])).await?;
        for receipt in receipts.receipts.into_iter().rev() {
            if receipt.peer_address.as_deref() != Some(&info.address)
                || activity.iter().any(|op| op.txid == receipt.txid)
            {
                continue;
            }
            activity.insert(
                0,
                Operation {
                    txid: receipt.txid,
                    opening_hex: info.opening_hex.clone(),
                    address: info.address.clone(),
                    kind: OperationKind::Funding,
                    amount_micronoid: Some(receipt.amount_micronoid),
                    fee_micronoid: Some(receipt.fee_micronoid),
                    authority: None,
                    recipient: Some(info.address.clone()),
                    call_height: None,
                    confirmation: None,
                    canonical: false,
                    receipt_available: false,
                },
            );
        }
        activity.truncate(ACTIVITY_LIMIT);
        // Work is bounded by the local activity window; header checks are cheap.
        let mut hashes = std::collections::BTreeMap::<u64, Option<String>>::new();
        for operation in &mut activity {
            operation.canonical = false;
            operation.receipt_available = false;
            if let Some(confirmation) = &operation.confirmation {
                if let std::collections::btree_map::Entry::Vacant(e) =
                    hashes.entry(confirmation.height)
                {
                    let hash = self
                        .contract_rpc("getBlockHash", json!([confirmation.height]))
                        .await?;
                    e.insert(hash);
                }
                operation.canonical =
                    hashes[&confirmation.height].as_deref() == Some(&confirmation.block_hash);
            }
            if !operation.canonical {
                let tx: Option<Value> = self.contract_rpc("getTx", json!([operation.txid])).await?;
                if let Some(tx) = tx {
                    if tx["tx_hash"] == operation.txid {
                        operation.confirmation = Some(Confirmation {
                            height: tx["height"].as_u64().ok_or("Invalid transaction height.")?,
                            block_hash: tx["block_hash"]
                                .as_str()
                                .ok_or("Invalid block hash.")?
                                .to_owned(),
                        });
                        operation.canonical = true;
                    }
                }
            }
            // Bodies are pruned. A GUI that was closed at confirmation can
            // still recover its record from the node's retained wallet proof.
            if operation.confirmation.is_none() {
                if let Ok(encoded) = self.operation_proof(operation).await {
                    let proof = SharedProof {
                        kind: if operation.kind == OperationKind::Funding {
                            ReceiptKind::Funding
                        } else {
                            ReceiptKind::Call
                        },
                        receipt_hex: encoded,
                    };
                    let original: Option<Info> = if proof.kind == ReceiptKind::Funding {
                        Some(
                            self.contract_rpc("walletWatchObject", json!([operation.opening_hex]))
                                .await?,
                        )
                    } else {
                        None
                    };
                    if let Ok((_, checked)) =
                        self.check_shared_proof(original.as_ref(), &proof).await
                    {
                        if checked.txid == operation.txid {
                            operation.confirmation = checked.confirmation;
                            operation.canonical = true;
                        }
                    }
                }
            }
            if operation.canonical {
                // A recursive receipt can lag confirmation until a descendant
                // supplies its terminal. Retry at the next block without calling it failed.
                // Presence is sufficient for the button; export verifies the
                // contents. Do not reread megabytes of cached proofs on every block.
                operation.receipt_available = operation
                    .confirmation
                    .as_ref()
                    .is_some_and(|c| retained.get(&operation.txid) == Some(&c.block_hash))
                    || tokio::fs::try_exists(self.operation_proof_path(operation)?)
                        .await
                        .map_err(|e| e.to_string())?
                    || self.operation_proof(operation).await.is_ok();
            }
        }
        activity.sort_by_key(|op| {
            std::cmp::Reverse(
                op.confirmation
                    .as_ref()
                    .map(|c| c.height)
                    .or(op.call_height)
                    .unwrap_or(u64::MAX),
            )
        });
        self.persist_activity(info, &activity).await?;
        Ok(activity)
    }

    async fn check_shared_proof(
        &self,
        info: Option<&Info>,
        proof: &SharedProof,
    ) -> Result<(Option<VerifiedReceipt>, Operation), String> {
        self.check_shared_proof_mode(info, proof, false).await
    }

    async fn check_shared_proof_mode(
        &self,
        info: Option<&Info>,
        proof: &SharedProof,
        retain: bool,
    ) -> Result<(Option<VerifiedReceipt>, Operation), String> {
        if proof.receipt_hex.len() > RECEIPT_LIMIT * 2 {
            return Err("Receipt exceeds its file limit.".into());
        }
        // Keep the verified receipt and its stored confirmation on the same
        // selected ancestry even if a reorg happens between RPC responses.
        let tip: Value = self.contract_rpc("getChainInfo", json!([])).await?;
        let anchor_height = tip["height"].as_u64().ok_or("Invalid chain tip.")?;
        let anchor_hash = tip["best_hash"].as_str().ok_or("Invalid chain tip.")?;
        let mut funding_authority = None;
        let (call, txid, height, address, opening_hex, kind, amount, fee) = match proof.kind {
            ReceiptKind::Funding => {
                let info =
                    info.ok_or("A payment receipt needs the contract file to restore its rules.")?;
                let verified: RpcReceiptVerifyResult = self
                    .contract_rpc("verifyReceipt", json!([proof.receipt_hex]))
                    .await?;
                if !verified.merkle_valid || !verified.canonical || !verified.confirmed {
                    return Err("Funding receipt is not confirmed on this chain.".into());
                }
                let summary = verified
                    .authenticated_summary
                    .ok_or("Funding receipt has no authenticated payment.")?;
                let amount = funding_amount(&summary, &info.address)?;
                funding_authority = summary
                    .inputs
                    .first()
                    .filter(|first| {
                        summary
                            .inputs
                            .iter()
                            .all(|input| input.owner == first.owner)
                    })
                    .map(|input| input.owner.clone());
                (
                    None,
                    summary.txid,
                    summary.claimed_height,
                    info.address.clone(),
                    info.opening_hex.clone(),
                    OperationKind::Funding,
                    Some(amount),
                    Some(summary.fee_micronoid),
                )
            }
            ReceiptKind::Call => {
                let checked: Value = self
                    .contract_rpc(
                        if retain {
                            "walletImportObjectReceipt"
                        } else {
                            "verifyObjectReceipt"
                        },
                        if retain {
                            json!([proof.receipt_hex, info.map(|i| &i.opening_hex)])
                        } else {
                            json!([proof.receipt_hex])
                        },
                    )
                    .await?;
                if checked["valid"] != true {
                    return Err("Contract receipt did not verify.".into());
                }
                txid(&checked)?;
                let receipt: VerifiedReceipt =
                    serde_json::from_value(checked).map_err(|e| e.to_string())?;
                validate_call(&receipt)?;
                if let Some(info) = info {
                    if receipt.original.opening_hex != info.opening_hex
                        && receipt
                            .successor
                            .as_ref()
                            .is_none_or(|next| next.opening_hex != info.opening_hex)
                    {
                        return Err(
                            "The receipt does not establish the contract state in this file."
                                .into(),
                        );
                    }
                }
                let result = (
                    Some(receipt.clone()),
                    receipt.txid.clone(),
                    receipt.height,
                    receipt.original.address.clone(),
                    receipt.original.opening_hex.clone(),
                    if receipt.terminal {
                        OperationKind::Withdrawal
                    } else if receipt.payout.is_some() {
                        OperationKind::Payment
                    } else {
                        OperationKind::Update
                    },
                    Some(receipt.payout.as_ref().map_or(0, |p| p.amount_micronoid)),
                    Some(receipt.fee_micronoid),
                );
                result
            }
        };
        let block_hash: Option<String> = self.contract_rpc("getBlockHash", json!([height])).await?;
        let anchor: Option<String> = self
            .contract_rpc("getBlockHash", json!([anchor_height]))
            .await?;
        if height > anchor_height || anchor.as_deref() != Some(anchor_hash) {
            return Err("The chain changed while checking this file. Open it again.".into());
        }
        let operation = Operation {
            txid,
            opening_hex,
            address,
            kind,
            amount_micronoid: amount,
            fee_micronoid: fee,
            authority: call
                .as_ref()
                .map(|c| c.authority.clone())
                .or(funding_authority),
            recipient: call
                .as_ref()
                .and_then(|c| c.payout.as_ref().map(|p| p.address.clone()))
                .or_else(|| {
                    (proof.kind == ReceiptKind::Funding).then(|| info.unwrap().address.clone())
                }),
            call_height: (proof.kind == ReceiptKind::Call).then_some(height),
            confirmation: Some(Confirmation {
                height,
                block_hash: block_hash.ok_or("Receipt block is no longer selected.")?,
            }),
            canonical: true,
            receipt_available: true,
        };
        Ok((call, operation))
    }

    pub(super) async fn open_contract_file(&self, path: Option<String>) -> Result<Outcome, String> {
        let path = if let Some(path) = path {
            PathBuf::from(path)
        } else {
            let Some(file) = rfd::AsyncFileDialog::new()
                .set_title("Open contract or receipt")
                .add_filter("Contract or receipt", &["json", "receipt"])
                .pick_file()
                .await
            else {
                return Ok(Outcome::Notice(
                    "No file selected. You can also paste its full path and choose Open file."
                        .into(),
                ));
            };
            file.path().to_owned()
        };
        self.read_contract_file(&path).await.map(Outcome::Opened)
    }

    async fn read_contract_file(&self, path: &Path) -> Result<OpenedFile, String> {
        let bytes = read_file(path, CONTRACT_FILE_LIMIT).await?;
        let mut result = OpenedFile {
            file_name: path.to_string_lossy().into_owned(),
            name: String::new(),
            info: None,
            instances: None,
            proof: None,
            verified_call: None,
            operation: None,
        };
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            let opening = if value.get("format").is_some() {
                let file: ContractFile =
                    serde_json::from_value(value).map_err(|e| e.to_string())?;
                if file.format != "parano1d-contract" || file.version != 1 {
                    return Err("Unsupported contract file version.".into());
                }
                validate_name(&file.name)?;
                result.name = file.name;
                result.proof = file.proof;
                file.opening_hex
            } else {
                value["opening_hex"]
                    .as_str()
                    .or_else(|| value["successor"]["opening_hex"].as_str())
                    .ok_or(
                        "This file has no contract rules. Ask the sender to use Share contract.",
                    )?
                    .to_owned()
            };
            if opening.len() > 4096 {
                return Err("Contract terms exceed their size limit.".into());
            }
            let info: Info = self
                .contract_rpc("walletWatchObject", json!([opening]))
                .await?;
            if !info.has_program_details() {
                return Err("Contract program details are incomplete.".into());
            }
            result.info = Some(info);
        } else {
            if bytes.len() > RECEIPT_LIMIT {
                return Err("Receipt exceeds its file limit.".into());
            }
            result.proof = Some(SharedProof {
                kind: ReceiptKind::Call,
                receipt_hex: hex::encode(bytes),
            });
        }
        if let Some(proof) = &result.proof {
            let (call, operation) = self.check_shared_proof(result.info.as_ref(), proof).await?;
            if result.info.is_none() {
                result.info = call.as_ref().map(|call| {
                    call.successor
                        .clone()
                        .unwrap_or_else(|| call.original.clone())
                });
            }
            result.verified_call = call;
            result.operation = Some(operation);
        }
        if let Some(info) = &result.info {
            result.instances = Some(
                self.contract_rpc("getObjectInstances", json!([info.opening_hex, 0, 32]))
                    .await?,
            );
        }
        Ok(result)
    }

    pub(super) async fn accept_contract_file(&self, file: OpenedFile) -> Result<Outcome, String> {
        let info = file.info.ok_or("This receipt records a closed balance.")?;
        // Recheck before adding it: the file preview may be several blocks old.
        let checked = if let Some(proof) = file.proof {
            let (_, operation) = self
                .check_shared_proof_mode(Some(&info), &proof, true)
                .await?;
            Some((proof, operation))
        } else {
            None
        };
        // Raw call receipts also establish a successor opening. Register it
        // so this wallet follows later calls made by another participant.
        let info: Info = self
            .contract_rpc("walletWatchObject", json!([info.opening_hex]))
            .await?;
        self.remember_contract_metadata(&info, &file.name, None, Source::Imported)
            .await?;
        if let Some((proof, operation)) = checked {
            persist_artifact(
                self.operation_proof_path(&operation)?,
                hex::decode(proof.receipt_hex).map_err(|e| e.to_string())?,
            )
            .await?;
            self.remember_operation(&info, operation).await?;
        }
        let loaded = self.contract_instances(info, 0).await?;
        Ok(Outcome::WithNotice(
            Box::new(loaded),
            "Contract saved. Existing operations were kept; current balances were checked on this node.".into(),
        ))
    }

    async fn contract_share_file(&self, info: &Info) -> Result<ContractFile, String> {
        let library = self.contract_library().await?;
        let name = library
            .iter()
            .find(|e| e.info.family_key() == info.family_key())
            .map(|e| e.name.clone())
            .unwrap_or_default();
        let mut proof = None;
        // Include a proof only when it binds to these exact rules / counters.
        for operation in self
            .contract_activity(info)
            .await?
            .iter()
            .filter(|op| op.canonical && op.receipt_available)
            .take(8)
        {
            let candidate = SharedProof {
                kind: if operation.kind == OperationKind::Funding {
                    ReceiptKind::Funding
                } else {
                    ReceiptKind::Call
                },
                receipt_hex: self.operation_proof(operation).await?,
            };
            if self
                .check_shared_proof(Some(info), &candidate)
                .await
                .is_ok()
            {
                proof = Some(candidate);
                break;
            }
        }
        Ok(ContractFile {
            format: "parano1d-contract".into(),
            version: 1,
            name,
            opening_hex: info.opening_hex.clone(),
            proof,
        })
    }

    pub(super) async fn share_contract(&self, info: &Info) -> Result<Outcome, String> {
        let file = self.contract_share_file(info).await?;
        let Some(destination) = rfd::AsyncFileDialog::new()
            .set_title("Share contract")
            .set_file_name("contract.json")
            .add_filter("Contract", &["json"])
            .save_file()
            .await
        else {
            return Ok(Outcome::Notice("File saving cancelled.".into()));
        };
        destination
            .write(&serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Outcome::Notice(if file.proof.is_some() { "Contract file saved with a verified operation receipt. Share it with the other participant." } else { "Contract rules saved. The recipient will check current balances when opening this file." }.into()))
    }

    pub(super) async fn save_operation_receipt(
        &self,
        _info: &Info,
        operation: &Operation,
    ) -> Result<Outcome, String> {
        let (name, bytes) = self.operation_receipt_file(operation).await?;
        save_bytes(&name, bytes).await
    }

    async fn operation_receipt_file(
        &self,
        operation: &Operation,
    ) -> Result<(String, Vec<u8>), String> {
        let proof = SharedProof {
            kind: if operation.kind == OperationKind::Funding {
                ReceiptKind::Funding
            } else {
                ReceiptKind::Call
            },
            receipt_hex: self.operation_proof(operation).await?,
        };
        if proof.kind == ReceiptKind::Funding {
            let original: Info = self
                .contract_rpc("walletWatchObject", json!([operation.opening_hex]))
                .await?;
            self.check_shared_proof(Some(&original), &proof).await?;
            // Include the original rules so a funding receipt is usable by its recipient.
            let file = ContractFile {
                format: "parano1d-contract".into(),
                version: 1,
                name: String::new(),
                opening_hex: original.opening_hex,
                proof: Some(proof),
            };
            Ok((
                format!("{}.json", operation.txid),
                serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?,
            ))
        } else {
            let (verified, _) = self.check_shared_proof(None, &proof).await?;
            if verified
                .as_ref()
                .is_none_or(|receipt| receipt.txid != operation.txid)
            {
                return Err("Receipt verification did not match the requested call.".into());
            }
            Ok((
                format!("{}.receipt", operation.txid),
                hex::decode(proof.receipt_hex).map_err(|e| e.to_string())?,
            ))
        }
    }
}

fn validate_call(call: &VerifiedReceipt) -> Result<(), String> {
    let total = call
        .retained_micronoid
        .checked_add(call.fee_micronoid)
        .and_then(|v| v.checked_add(call.payout.as_ref().map_or(0, |p| p.amount_micronoid)));
    if total != Some(call.input_micronoid)
        || call.terminal != call.successor.is_none()
        || (call.terminal && call.retained_micronoid != 0)
    {
        return Err("Invalid contract receipt amounts or successor.".into());
    }
    Ok(())
}

fn call_operation(call: &VerifiedReceipt, block_hash: String, canonical: bool) -> Operation {
    Operation {
        txid: call.txid.clone(),
        opening_hex: call.original.opening_hex.clone(),
        address: call.original.address.clone(),
        kind: if call.terminal {
            OperationKind::Withdrawal
        } else if call.payout.is_some() {
            OperationKind::Payment
        } else {
            OperationKind::Update
        },
        amount_micronoid: Some(call.payout.as_ref().map_or(0, |p| p.amount_micronoid)),
        fee_micronoid: Some(call.fee_micronoid),
        authority: Some(call.authority.clone()),
        recipient: call.payout.as_ref().map(|p| p.address.clone()),
        call_height: Some(call.height),
        confirmation: Some(Confirmation {
            height: call.height,
            block_hash,
        }),
        canonical,
        receipt_available: canonical,
    }
}

fn merge_operation(activity: &mut Vec<Operation>, operation: Operation) -> Result<(), String> {
    if !operation.valid() {
        return Err("Invalid contract operation.".into());
    }
    if let Some(old) = activity.iter_mut().find(|old| old.txid == operation.txid) {
        // The same logical transaction cannot have conflicting public amounts.
        for (known, incoming) in [
            (old.amount_micronoid, operation.amount_micronoid),
            (old.fee_micronoid, operation.fee_micronoid),
        ] {
            if known.zip(incoming).is_some_and(|(a, b)| a != b) {
                return Err("Saved operation conflicts with its verified receipt.".into());
            }
        }
        old.amount_micronoid = old.amount_micronoid.or(operation.amount_micronoid);
        old.fee_micronoid = old.fee_micronoid.or(operation.fee_micronoid);
        if operation.canonical {
            old.authority = operation.authority.or(old.authority.take());
            old.recipient = operation.recipient.or(old.recipient.take());
        } else {
            old.authority = old.authority.take().or(operation.authority);
            old.recipient = old.recipient.take().or(operation.recipient);
        }
        if operation.canonical || old.confirmation.is_none() {
            old.kind = operation.kind;
            old.address = operation.address;
            old.opening_hex = operation.opening_hex;
            old.call_height = operation.call_height;
            old.confirmation = operation.confirmation;
            old.canonical = operation.canonical;
            old.receipt_available = operation.receipt_available;
        }
    } else {
        activity.insert(0, operation);
    }
    activity.sort_by_key(|op| {
        std::cmp::Reverse(
            op.confirmation
                .as_ref()
                .map(|c| c.height)
                .or(op.call_height)
                .unwrap_or(u64::MAX),
        )
    });
    // Only this recent index is capped. Retained proof files are never removed.
    activity.truncate(ACTIVITY_LIMIT);
    Ok(())
}

fn funding_amount(summary: &RpcReceiptSummary, address: &str) -> Result<u64, String> {
    let amount = summary
        .outputs
        .iter()
        .filter(|output| output.owner == address)
        .try_fold(0u64, |sum, output| sum.checked_add(output.amount_micronoid))
        .ok_or("Funding amount overflow.")?;
    if amount == 0 {
        return Err("The receipt does not fund the contract in this file.".into());
    }
    Ok(amount)
}

async fn persist_artifact(path: PathBuf, bytes: Vec<u8>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(path.parent().ok_or("Missing contract storage directory.")?)
            .map_err(|e| e.to_string())?;
        persist_owner_only_atomically(&path, &bytes, "contract artifact")
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn save_bytes(name: &str, bytes: Vec<u8>) -> Result<Outcome, String> {
    let Some(file) = rfd::AsyncFileDialog::new()
        .set_title("Save verified receipt")
        .set_file_name(name)
        .save_file()
        .await
    else {
        return Ok(Outcome::Notice("File saving cancelled.".into()));
    };
    file.write(&bytes).await.map_err(|e| e.to_string())?;
    Ok(Outcome::Notice("Verified operation receipt saved.".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn rpc_backend(
        directory: &Path,
        reply: impl Fn(&Value) -> Value + Send + Sync + 'static,
    ) -> (
        Backend,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let backend = super::super::tests::backend(directory);
        backend.inner.config.lock().unwrap().rpc_url =
            format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let request = loop {
                    let mut buffer = [0; 8192];
                    let count = socket.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    data.extend_from_slice(&buffer[..count]);
                    assert!(data.len() < 128 * 1024);
                    if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                        let length: usize = header
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .unwrap()
                            .trim()
                            .parse()
                            .unwrap();
                        if data.len() >= end + 4 + length {
                            break serde_json::from_slice::<Value>(
                                &data[end + 4..end + 4 + length],
                            )
                            .unwrap();
                        }
                    }
                };
                if request["method"] == "paranoid_walletReceipts" {
                    assert!(request["params"][1].as_u64().unwrap() <= 50);
                }
                recorded
                    .lock()
                    .unwrap()
                    .push(request["method"].as_str().unwrap().to_owned());
                let response = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0", "id":request["id"], "result":reply(&request)}),
                )
                .unwrap();
                let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&response).await.unwrap();
            }
        });
        (backend, calls, task)
    }

    fn operation() -> Operation {
        let info = crate::contracts::tests::info();
        Operation {
            txid: "ab".repeat(32),
            opening_hex: info.opening_hex,
            address: info.address,
            kind: OperationKind::Funding,
            amount_micronoid: Some(10_000_000),
            fee_micronoid: Some(5800),
            authority: None,
            recipient: None,
            call_height: None,
            confirmation: Some(Confirmation {
                height: 9,
                block_hash: "12".repeat(32),
            }),
            canonical: true,
            receipt_available: true,
        }
    }

    #[tokio::test]
    async fn creating_and_funding_stops_at_a_quote_until_confirmation() {
        let directory = tempfile::tempdir().unwrap();
        let (backend, calls, server) = rpc_backend(directory.path(), |request| {
            match request["method"].as_str().unwrap() {
                "paranoid_createObject" => {
                    serde_json::to_value(crate::contracts::tests::info()).unwrap()
                }
                "paranoid_walletActiveAddress" => json!({"address":"spending-key"}),
                "paranoid_walletPlanSend" => json!({"fee_micronoid":5800}),
                other => panic!("unexpected signing or mutation: {other}"),
            }
        })
        .await;
        let outcome = backend
            .contract_operation(Request::CreateAndFund {
                definition: json!({}),
                creation: Creation {
                    name: "Savings".into(),
                    kind: crate::contracts::Kind::Vault,
                },
                amount: 10_000_000,
                fee: 0,
                sender: "spending-key".into(),
            })
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            Outcome::FundingReview {
                fee: 5800,
                creation: Some(_),
                ..
            }
        ));
        assert_eq!(calls.lock().unwrap().len(), 3);
        assert!(!directory.path().join("wallet.contracts.json").exists());
        server.abort();
    }

    #[tokio::test]
    async fn received_unicode_file_uses_node_rules_and_does_not_add_a_wallet_entry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Полученный контракт 東京.json");
        let mut untrusted = serde_json::to_value(crate::contracts::tests::info()).unwrap();
        untrusted["claim_authority"] = json!("file-supplied-wrong-authority");
        tokio::fs::write(&path, serde_json::to_vec(&untrusted).unwrap())
            .await
            .unwrap();
        let (backend, _, server) = rpc_backend(directory.path(), |request| {
            match request["method"].as_str().unwrap() {
                "paranoid_walletWatchObject" => {
                    serde_json::to_value(crate::contracts::tests::info()).unwrap()
                }
                "paranoid_getObjectInstances" => json!({"height":50,"slots":[],"next_slot":null}),
                other => panic!("unexpected mutation: {other}"),
            }
        })
        .await;
        let file = backend.read_contract_file(&path).await.unwrap();
        assert_eq!(file.info.unwrap().claim_authority, "spending-key");
        assert_eq!(file.file_name, path.to_string_lossy());
        assert!(!directory.path().join("wallet.contracts.json").exists());
        server.abort();
    }

    #[test]
    fn funding_receipt_must_pay_the_exact_contract() {
        let mut summary = RpcReceiptSummary {
            txid: "ab".repeat(32),
            claimed_height: 8,
            confirmed_unix: 0,
            tx_index: 1,
            tx_count: 2,
            fee_micronoid: 5800,
            inputs: vec![],
            outputs: vec![RpcReceiptOutput {
                slot_index: 7,
                owner: "different-contract".into(),
                amount_micronoid: 10,
            }],
        };
        assert!(funding_amount(&summary, "contract").is_err());
        summary.outputs[0].owner = "contract".into();
        assert_eq!(funding_amount(&summary, "contract").unwrap(), 10);
    }

    #[tokio::test]
    async fn reorg_removes_confirmation_and_receipt_actions_even_with_a_saved_file() {
        let directory = tempfile::tempdir().unwrap();
        let (backend, _, server) = rpc_backend(directory.path(), |request| {
            match request["method"].as_str().unwrap() {
                "paranoid_walletListObjectReceipts" => {
                    json!({"height":50,"tip_hash":"ff".repeat(32),"entries":[],"next_cursor":null})
                }
                "paranoid_walletReceipts" => {
                    json!({"page":1,"page_size":50,"total":0,"total_pages":1,"receipts":[]})
                }
                "paranoid_getBlockHash" => json!("ff".repeat(32)),
                "paranoid_getTx" => Value::Null,
                other => panic!("unexpected: {other}"),
            }
        })
        .await;
        let info = crate::contracts::tests::info();
        let op = operation();
        backend.remember_operation(&info, op.clone()).await.unwrap();
        persist_artifact(backend.proof_path(&op.txid).unwrap(), vec![0; 12])
            .await
            .unwrap();
        let activity = backend.contract_activity(&info).await.unwrap();
        assert!(!activity[0].canonical);
        assert!(!activity[0].receipt_available);
        assert_eq!(activity[0].status(50), "CHAIN CHANGED");
        server.abort();
    }

    #[tokio::test]
    async fn activity_survives_replacement_restart_and_unicode_directories() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Контракты 東京 with spaces");
        let info = crate::contracts::tests::info();
        let first = super::super::tests::backend(&path);
        first.remember_operation(&info, operation()).await.unwrap();
        let mut second = operation();
        second.txid = "cd".repeat(32);
        first.remember_operation(&info, second).await.unwrap();
        drop(first);
        let reopened = super::super::tests::backend(&path);
        let activity = reopened.read_activity(&info).await.unwrap();
        assert_eq!(activity.len(), 2);
        assert_eq!(activity[0].txid, "cd".repeat(32));
        assert!(!activity[0].canonical);
        assert!(reopened.proof_path("../../outside").is_err());
        let mut successor = info.clone();
        successor.state[0] = "123".into();
        assert_eq!(info.family_key(), successor.family_key());
        assert_eq!(reopened.read_activity(&successor).await.unwrap().len(), 2);
        successor.deadline_height += 1;
        assert_ne!(info.family_key(), successor.family_key());
    }
    fn verified_funding() -> Value {
        json!({"merkle_valid":true,"canonical":true,"confirmed":true,
            "authenticated_summary": {"txid":"ab".repeat(32), "claimed_height":9,
                "confirmed_unix":0,"tx_index":1,"tx_count":2,"fee_micronoid":5800,
                "inputs":[], "outputs":[{"slot_index":7,"owner":crate::contracts::tests::info().address,"amount_micronoid":10_000_000}]}})
    }

    fn verified_call(terminal: bool) -> Value {
        let original = crate::contracts::tests::info();
        let mut next = original.clone();
        next.state[0] = "1".into();
        next.opening_hex = "bc".repeat(699);
        next.address = "successor-address".into();
        json!({"valid":true, "height":9, "txid":"cd".repeat(32),
            "terminal":terminal, "authority":"other-participant", "original":original,
            "successor":if terminal {Value::Null} else {serde_json::to_value(next).unwrap()},
            "input_micronoid":10_000_000, "fee_micronoid":5800,
            "retained_micronoid":if terminal {0} else {8_994_200},
            "payout":{"address":"payee","amount_micronoid":if terminal {9_994_200} else {1_000_000}}})
    }

    #[tokio::test]
    async fn other_participant_calls_merge_without_reading_proofs_or_losing_own_records() {
        let directory = tempfile::tempdir().unwrap();
        let (backend, calls, server) = rpc_backend(directory.path(), |request| {
            match request["method"].as_str().unwrap() {
                "paranoid_walletListObjectReceipts" => {
                    let mut entry = verified_call(false);
                    entry["block_hash"] = json!("12".repeat(32));
                    entry["canonical"] = json!(true);
                    json!({"height":50,"tip_hash":"12".repeat(32),"entries":[entry],"next_cursor":null})
                }
                "paranoid_walletReceipts" => json!({"page":1,"page_size":50,"total":0,"total_pages":1,"receipts":[]}),
                "paranoid_getBlockHash" => json!("12".repeat(32)),
                other => panic!("unexpected proof read or verification: {other}"),
            }
        }).await;
        let info = crate::contracts::tests::info();
        let own = operation();
        backend
            .remember_operation(&info, own.clone())
            .await
            .unwrap();
        persist_artifact(backend.operation_proof_path(&own).unwrap(), vec![42])
            .await
            .unwrap();
        // Upgrade a previously imported call whose old response omitted amounts.
        let mut old = own.clone();
        old.txid = "cd".repeat(32);
        old.kind = OperationKind::Update;
        old.amount_micronoid = None;
        old.fee_micronoid = None;
        backend.remember_operation(&info, old).await.unwrap();
        for _ in 0..2 {
            let activity = backend.contract_activity(&info).await.unwrap();
            assert_eq!(activity.len(), 2);
            let call = activity.iter().find(|o| o.txid == "cd".repeat(32)).unwrap();
            assert_eq!(call.kind, OperationKind::Payment);
            assert_eq!(call.authority.as_deref(), Some("other-participant"));
            assert_eq!(call.amount_micronoid, Some(1_000_000));
            assert!(call.canonical && call.receipt_available);
            assert_eq!(
                activity
                    .iter()
                    .find(|o| o.txid == own.txid)
                    .unwrap()
                    .amount_micronoid,
                own.amount_micronoid
            );
        }
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.contains("exportObjectReceipt") || c.contains("verifyObjectReceipt")));
        server.abort();
    }

    #[tokio::test]
    async fn closing_receipt_and_stale_update_keep_local_name_records_and_live_successor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Закрытие 東京.receipt");
        tokio::fs::write(&path, [0xab, 0xcd]).await.unwrap();
        let (backend, calls, server) = rpc_backend(directory.path(), |request| {
            let original = crate::contracts::tests::info();
            let next = verified_call(false)["successor"].clone();
            match request["method"].as_str().unwrap() {
                "paranoid_getChainInfo" => json!({"height":50,"best_hash":"12".repeat(32)}),
                "paranoid_getBlockHash" => json!("12".repeat(32)),
                "paranoid_verifyObjectReceipt" => verified_call(true),
                "paranoid_walletImportObjectReceipt" => {
                    assert_eq!(request["params"][1], original.opening_hex);
                    verified_call(true)
                }
                "paranoid_walletWatchObject" => serde_json::to_value(original).unwrap(),
                "paranoid_getObjectInstances" => {
                    let slots = if request["params"][0] == next["opening_hex"] {
                        json!([{"slot_index":8,"value":8_994_200,"creation_id":123}])
                    } else {json!([])};
                    json!({"height":50,"slots":slots,"next_slot":null})
                }
                "paranoid_walletListObjectStates" => json!({"height":50,"states":[{"object":next,"has_balance":true}],"next_root":null}),
                "paranoid_walletListObjectReceipts" => json!({"height":50,"tip_hash":"12".repeat(32),"entries":[],"next_cursor":null}),
                "paranoid_walletReceipts" => json!({"page":1,"page_size":50,"total":0,"total_pages":1,"receipts":[]}),
                other => panic!("unexpected: {other}"),
            }
        }).await;
        let info = crate::contracts::tests::info();
        backend
            .remember_contract_metadata(&info, "My own name", None, Source::Created)
            .await
            .unwrap();
        let own = operation();
        backend
            .remember_operation(&info, own.clone())
            .await
            .unwrap();
        persist_artifact(backend.operation_proof_path(&own).unwrap(), vec![42])
            .await
            .unwrap();
        for _ in 0..2 {
            let mut opened = backend.read_contract_file(&path).await.unwrap();
            assert_eq!(opened.info.as_ref().unwrap().opening_hex, info.opening_hex);
            assert_eq!(
                opened.operation.as_ref().unwrap().kind,
                OperationKind::Withdrawal
            );
            opened.name = "Sender's name".into();
            backend.accept_contract_file(opened).await.unwrap();
            let library = backend.contract_library().await.unwrap();
            assert_eq!(library.len(), 1);
            assert_eq!(library[0].name, "My own name");
            assert_eq!(library[0].info.address, "successor-address");
            let activity = backend.read_activity(&info).await.unwrap();
            assert_eq!(activity.len(), 2);
            assert!(activity.iter().any(|op| op.txid == own.txid));
        }
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| *c == "paranoid_walletImportObjectReceipt")
                .count(),
            2
        );
        server.abort();
    }

    #[test]
    fn conflicting_receipt_never_replaces_local_amounts() {
        let mut records = vec![operation()];
        let mut conflicting = operation();
        conflicting.amount_micronoid = Some(1);
        assert!(merge_operation(&mut records, conflicting).is_err());
        assert_eq!(records[0].amount_micronoid, Some(10_000_000));
    }

    #[tokio::test]
    async fn imported_funding_receipt_does_not_stand_in_for_current_balance() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("contract.json");
        let file = ContractFile {
            format: "parano1d-contract".into(),
            version: 1,
            name: "Received payment".into(),
            opening_hex: crate::contracts::tests::info().opening_hex,
            proof: Some(SharedProof {
                kind: ReceiptKind::Funding,
                receipt_hex: "abcd".into(),
            }),
        };
        tokio::fs::write(&path, serde_json::to_vec(&file).unwrap())
            .await
            .unwrap();
        let balance = Arc::new(AtomicU64::new(4_000_000));
        let current = balance.clone();
        let (backend, _, server) = rpc_backend(directory.path(), move |request| {
            match request["method"].as_str().unwrap() {
                "paranoid_walletWatchObject" => {
                    serde_json::to_value(crate::contracts::tests::info()).unwrap()
                }
                "paranoid_getChainInfo" => json!({"height":50,"best_hash":"12".repeat(32)}),
                "paranoid_verifyReceipt" => verified_funding(),
                "paranoid_getBlockHash" => json!("12".repeat(32)),
                "paranoid_getObjectInstances" => {
                    let amount = current.load(Ordering::SeqCst);
                    let slots = if amount > 0 {
                        json!([{"slot_index":8,"value":amount,"creation_id":123}])
                    } else {
                        json!([])
                    };
                    json!({"height":50,"slots":slots,"next_slot":null})
                }
                other => panic!("unexpected mutation: {other}"),
            }
        })
        .await;
        for amount in [4_000_000, 0] {
            balance.store(amount, Ordering::SeqCst);
            let opened = backend.read_contract_file(&path).await.unwrap();
            let receipt = opened.operation.unwrap();
            assert!(receipt.canonical);
            assert_eq!(receipt.amount_micronoid, Some(10_000_000));
            assert_eq!(receipt.confirmation.unwrap().height, 9);
            let instances = opened.instances.unwrap();
            assert_eq!(instances.height, 50);
            assert_eq!(instances.slots.iter().map(|s| s.value).sum::<u64>(), amount);
        }
        assert!(!directory.path().join("wallet.contracts.json").exists());
        server.abort();
    }

    #[tokio::test]
    async fn pruned_transaction_recovers_confirmation_from_its_retained_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let (backend, calls, server) = rpc_backend(directory.path(), |request| {
            match request["method"].as_str().unwrap() {
                "paranoid_walletListObjectReceipts" => {
                    json!({"height":50,"tip_hash":"12".repeat(32),"entries":[],"next_cursor":null})
                }
                "paranoid_walletReceipts" => {
                    json!({"page":1,"page_size":50,"total":0,"total_pages":1,"receipts":[]})
                }
                "paranoid_getTx" => Value::Null,
                "paranoid_walletExportReceipt" => json!("abcd"),
                "paranoid_walletWatchObject" => {
                    serde_json::to_value(crate::contracts::tests::info()).unwrap()
                }
                "paranoid_getChainInfo" => json!({"height":50,"best_hash":"12".repeat(32)}),
                "paranoid_verifyReceipt" => verified_funding(),
                "paranoid_getBlockHash" => json!("12".repeat(32)),
                other => panic!("unexpected: {other}"),
            }
        })
        .await;
        let info = crate::contracts::tests::info();
        let mut pending = operation();
        pending.confirmation = None;
        backend.remember_operation(&info, pending).await.unwrap();
        let activity = backend.contract_activity(&info).await.unwrap();
        assert!(activity[0].canonical && activity[0].receipt_available);
        assert_eq!(activity[0].confirmation.as_ref().unwrap().height, 9);
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|m| *m == "paranoid_verifyReceipt")
                .count(),
            1
        );
        server.abort();
    }

    #[tokio::test]
    async fn reorg_during_file_acceptance_never_adds_the_contract() {
        let directory = tempfile::tempdir().unwrap();
        let (backend, _, server) = rpc_backend(directory.path(), |request| {
            match request["method"].as_str().unwrap() {
                "paranoid_getChainInfo" => json!({"height":50,"best_hash":"12".repeat(32)}),
                "paranoid_verifyReceipt" => verified_funding(),
                "paranoid_getBlockHash" => json!("ff".repeat(32)),
                other => panic!("unexpected write after reorg: {other}"),
            }
        })
        .await;
        let file = OpenedFile {
            file_name: "contract.json".into(),
            name: "Received".into(),
            info: Some(crate::contracts::tests::info()),
            instances: None,
            proof: Some(SharedProof {
                kind: ReceiptKind::Funding,
                receipt_hex: "abcd".into(),
            }),
            verified_call: None,
            operation: Some(operation()),
        };
        let error = backend.accept_contract_file(file).await.unwrap_err();
        assert!(error.contains("chain changed"));
        assert!(!directory.path().join("wallet.contracts.json").exists());
        server.abort();
    }
}
