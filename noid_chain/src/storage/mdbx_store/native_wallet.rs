// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded wallet holdings from one authenticated durable State snapshot.

use super::*;
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::NativeOpening;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeWalletCursor {
    pub owner: [u8; 32],
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub after_root: Option<[u8; 32]>,
    pub from_slot: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWalletItem {
    pub root: [u8; 32],
    pub opening: NativeOpening,
    pub dependency: Option<NativeOpening>,
    pub carrier: VerifiedOwnerUtxo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWalletPage {
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub items: Vec<NativeWalletItem>,
    pub next: Option<NativeWalletCursor>,
}

#[derive(Debug)]
pub enum NativeWalletQueryError {
    Store(StoreError),
    Limit,
    TipChanged { height: u64, tip_hash: [u8; 32] },
}

impl From<StoreError> for NativeWalletQueryError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<libmdbx::Error> for NativeWalletQueryError {
    fn from(value: libmdbx::Error) -> Self {
        Self::Store(value.into())
    }
}

impl std::fmt::Display for NativeWalletQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => std::fmt::Display::fmt(error, f),
            Self::Limit => write!(f, "native wallet page limit must be 1..=256"),
            Self::TipChanged { .. } => write!(f, "native wallet State changed; restart pagination"),
        }
    }
}

impl std::error::Error for NativeWalletQueryError {}

impl MdbxStore {
    pub fn native_wallet_page(
        &self,
        owner: Address,
        cursor: Option<NativeWalletCursor>,
        limit: usize,
    ) -> Result<NativeWalletPage, NativeWalletQueryError> {
        if !(1..=256).contains(&limit) {
            return Err(NativeWalletQueryError::Limit);
        }
        let txn = self.db.begin_ro_txn()?;
        let tip_table = txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Vec<u8> = txn
            .get(&tip_table, KEY_TIP)?
            .ok_or(StoreError::Decode("native wallet tip missing"))?;
        let (height, tip_hash) =
            decode_chain_tip(&raw).ok_or(StoreError::Decode("native wallet tip encoding"))?;
        if cursor.is_some_and(|c| (c.height, c.tip_hash) != (height, tip_hash)) {
            return Err(NativeWalletQueryError::TipChanged { height, tip_hash });
        }
        if cursor.is_some_and(|c| c.owner != owner.0) {
            return Err(StoreError::Decode("native wallet cursor owner binding").into());
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let raw: Vec<u8> = txn
            .get(&headers, &u64_key(height))?
            .ok_or(StoreError::Decode("native wallet tip header missing"))?;
        let header =
            decode_header(&raw).ok_or(StoreError::Decode("native wallet tip header encoding"))?;
        if header.height != height || crate::block_id(&header) != tip_hash {
            return Err(StoreError::Decode("native wallet tip header binding").into());
        }
        let mut after_root = cursor.and_then(|c| c.after_root);
        let mut from_slot = cursor.map_or(0, |c| c.from_slot);
        let roots = super::super::native_payloads::owner_roots(&txn, owner, after_root, limit)?;
        let root_count = roots.len();
        let mut items = Vec::with_capacity(limit);
        let mut next = None;
        for (index, root) in roots.into_iter().enumerate() {
            let record = super::super::native_payloads::read(&txn, root)?
                .ok_or(StoreError::Decode("native wallet payload missing"))?;
            let dependency = record
                .opening
                .dependency_root()
                .map(|root| {
                    super::super::native_payloads::read(&txn, root.0)?
                        .map(|r| r.opening)
                        .ok_or(StoreError::Decode("native wallet dependency missing"))
                })
                .transpose()?;
            if !record
                .opening
                .owners_with_dependency(dependency)
                .map_err(|_| StoreError::Decode("native wallet authority binding"))?
                .contains(&owner)
            {
                return Err(StoreError::Decode("native wallet owner binding").into());
            }
            let remaining = limit - items.len();
            let mut carriers = Self::verified_owner_snapshot_in_txn(
                &txn,
                &root,
                Some(remaining + 1),
                Some(from_slot),
                true,
            )?;
            if (carriers.height, carriers.tip_hash, carriers.state_root)
                != (height, tip_hash, header.state_root)
            {
                return Err(StoreError::Decode("native wallet carrier State binding").into());
            }
            if carriers.utxos.len() as u64 > record.live_slots
                || (from_slot == 0 && carriers.utxos.is_empty())
            {
                return Err(StoreError::Decode("native wallet carrier count").into());
            }
            if from_slot == 0
                && carriers.utxos.len() <= remaining
                && carriers.utxos.len() as u64 != record.live_slots
            {
                return Err(StoreError::Decode("native wallet complete carrier count").into());
            }
            let following_slot = carriers.utxos.get(remaining).map(|u| u.slot_index);
            carriers.utxos.truncate(remaining);
            for carrier in carriers.utxos {
                record
                    .opening
                    .check_input_binding(
                        &noid_tx::TxInput {
                            slot_index: carrier.slot_index,
                            amount: carrier.amount,
                            creation_id: carrier.creation_id,
                        },
                        Address(root),
                    )
                    .map_err(|_| StoreError::Decode("native wallet carrier opening binding"))?;
                items.push(NativeWalletItem {
                    root,
                    opening: record.opening,
                    dependency,
                    carrier,
                });
            }
            if let Some(from_slot) = following_slot {
                next = Some(NativeWalletCursor {
                    owner: owner.0,
                    height,
                    tip_hash,
                    after_root,
                    from_slot,
                });
                break;
            }
            after_root = Some(root);
            from_slot = 0;
            if items.len() == limit {
                if index + 1 != root_count || root_count == limit {
                    next = Some(NativeWalletCursor {
                        owner: owner.0,
                        height,
                        tip_hash,
                        after_root,
                        from_slot,
                    });
                }
                break;
            }
        }
        if items.len() < limit && root_count == limit {
            next = Some(NativeWalletCursor {
                owner: owner.0,
                height,
                tip_hash,
                after_root,
                from_slot,
            });
        }
        Ok(NativeWalletPage {
            height,
            tip_hash,
            state_root: header.state_root,
            items,
            next,
        })
    }
}
