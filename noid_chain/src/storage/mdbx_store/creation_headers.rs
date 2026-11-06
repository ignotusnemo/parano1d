// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Resolve output birth blocks from permanent canonical headers.

use std::collections::BTreeMap;

use super::{
    decode_chain_tip, decode_header, u64_key, BlockHeader, MdbxStore, StoreError, KEY_TIP,
    T_CHAIN_TIP, T_HEADERS,
};
use crate::block_header::block_id;
use crate::consensus::params;

impl MdbxStore {
    /// Resolve creation IDs against one MVCC view of the canonical headers.
    /// Results retain the input order. Missing history yields an unknown birth.
    pub fn get_creation_headers(
        &self,
        creation_ids: &[u64],
    ) -> Result<Vec<Option<BlockHeader>>, StoreError> {
        if creation_ids.is_empty() {
            return Ok(Vec::new());
        }
        let txn = self.db.begin_ro_txn()?;
        let tips = txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Option<[u8; 40]> = txn.get(&tips, KEY_TIP)?;
        let Some((tip_height, tip_hash)) = raw.as_ref().and_then(|bytes| decode_chain_tip(bytes))
        else {
            return Ok(vec![None; creation_ids.len()]);
        };
        let headers = txn.open_table(Some(T_HEADERS))?;
        let mut cache = BTreeMap::new();
        let mut read = |height| -> Result<Option<BlockHeader>, StoreError> {
            if let Some(header) = cache.get(&height) {
                return Ok(Some(*header));
            }
            let raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
            let Some(raw) = raw else { return Ok(None) };
            let header =
                decode_header(&raw).ok_or(StoreError::Decode("creation header is malformed"))?;
            if header.height != height {
                return Err(StoreError::Decode("creation header height mismatch"));
            }
            // Shared binary-search pivots help large wallets without retaining
            // a decoded copy of the full header history.
            if cache.len() == 4096 {
                cache.clear();
            }
            cache.insert(height, header);
            Ok(Some(header))
        };
        let tip = read(tip_height)?.ok_or(StoreError::Decode(
            "creation lookup canonical tip is missing",
        ))?;
        if block_id(&tip) != tip_hash {
            return Err(StoreError::Decode("creation lookup canonical tip mismatch"));
        }
        creation_ids
            .iter()
            .map(|&id| find_creation_header(id, &tip, &mut read))
            .collect()
    }
}

fn find_creation_header(
    creation_id: u64,
    tip: &BlockHeader,
    read: &mut impl FnMut(u64) -> Result<Option<BlockHeader>, StoreError>,
) -> Result<Option<BlockHeader>, StoreError> {
    if params::is_coinbase_creation_id(creation_id) {
        let height = params::coinbase_creation_height(creation_id);
        return if height <= tip.height {
            read(height)
        } else {
            Ok(None)
        };
    }
    let native = params::v2_1_active(tip.height)
        && creation_id & noid_tx::native_assets::NATIVE_CREATION_TAG != 0;
    let sequence = if native {
        creation_id & noid_tx::native_assets::NATIVE_SEQUENCE_MAX
    } else {
        creation_id
    };
    if sequence == 0 || sequence > tip.alloc_counter {
        return Ok(None);
    }
    let (mut low, mut high) = (0, tip.height);
    while low < high {
        let middle = low + (high - low) / 2;
        let Some(header) = read(middle)? else {
            return Ok(None);
        };
        if header.alloc_counter < sequence {
            low = middle + 1
        } else {
            high = middle
        }
    }
    let Some(header) = read(low)? else {
        return Ok(None);
    };
    if header.alloc_counter < sequence || (native && !params::v2_1_active(header.height)) {
        return Ok(None);
    }
    if low > 0 {
        let Some(parent) = read(low - 1)? else {
            return Ok(None);
        };
        if parent.alloc_counter >= sequence {
            return Ok(None);
        }
    }
    Ok(Some(header))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u64, counter: u64) -> BlockHeader {
        let mut header = crate::consensus::genesis_header();
        header.height = height;
        header.alloc_counter = counter;
        header.timestamp = 1_000 + height * 30;
        header
    }

    #[test]
    fn creation_lookup_finds_first_allocation_and_handles_coinbase_namespace() {
        let headers = [header(0, 0), header(1, 2), header(2, 2), header(3, 5)];
        let mut read = |height| Ok(headers.get(height as usize).copied());
        for (id, wanted) in [(1, 1), (2, 1), (3, 3), (4, 3), (5, 3)] {
            assert_eq!(
                find_creation_header(id, &headers[3], &mut read)
                    .unwrap()
                    .unwrap()
                    .height,
                wanted
            );
        }
        assert!(find_creation_header(0, &headers[3], &mut read)
            .unwrap()
            .is_none());
        assert!(find_creation_header(6, &headers[3], &mut read)
            .unwrap()
            .is_none());
        let found = find_creation_header(params::coinbase_creation_id(2), &headers[3], &mut read)
            .unwrap()
            .unwrap();
        assert_eq!(found.height, 2);
        assert_eq!(found.timestamp, 1_060);
        assert!(
            find_creation_header(params::coinbase_creation_id(4), &headers[3], &mut read)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn creation_lookup_uses_the_current_branch_and_keeps_missing_history_unknown() {
        let tip = header(3, 5);
        let mut branch_a = |h| Ok(Some(header(h, [0, 2, 2, 5][h as usize])));
        let mut branch_b = |h| Ok(Some(header(h, [0, 1, 4, 5][h as usize])));
        assert_eq!(
            find_creation_header(2, &tip, &mut branch_a)
                .unwrap()
                .unwrap()
                .height,
            1
        );
        assert_eq!(
            find_creation_header(2, &tip, &mut branch_b)
                .unwrap()
                .unwrap()
                .height,
            2
        );
        let mut incomplete = |_| Ok(None);
        assert!(find_creation_header(2, &tip, &mut incomplete)
            .unwrap()
            .is_none());
    }

    #[test]
    fn creation_lookup_masks_native_sequence_and_checks_activation() {
        let activation = params::V2_1_ACTIVATION_HEIGHT.expect("scheduled native activation");
        let tip = header(activation + 1, 3);
        let mut read = |height| {
            Ok(Some(header(
                height,
                if height < activation {
                    1
                } else if height == activation {
                    2
                } else {
                    3
                },
            )))
        };
        let native = noid_tx::native_assets::NATIVE_CREATION_TAG;
        assert_eq!(
            find_creation_header(native | 2, &tip, &mut read)
                .unwrap()
                .unwrap()
                .height,
            activation
        );
        assert!(find_creation_header(native | 1, &tip, &mut read)
            .unwrap()
            .is_none());
    }

    #[test]
    fn creation_headers_batch_reads_current_canonical_rows_in_input_order() {
        use super::super::{encode_chain_tip, encode_header, WriteFlags};
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let install = |counters: [u64; 4]| {
            let txn = store.db.begin_rw_txn().unwrap();
            let headers = txn.open_table(Some(T_HEADERS)).unwrap();
            for (height, counter) in counters.into_iter().enumerate() {
                let h = header(height as u64, counter);
                txn.put(
                    &headers,
                    u64_key(h.height),
                    encode_header(&h),
                    WriteFlags::empty(),
                )
                .unwrap();
            }
            let tip = header(3, counters[3]);
            let tips = txn.open_table(Some(T_CHAIN_TIP)).unwrap();
            txn.put(
                &tips,
                KEY_TIP,
                encode_chain_tip(tip.height, &block_id(&tip)),
                WriteFlags::empty(),
            )
            .unwrap();
            txn.commit().unwrap();
        };
        install([0, 2, 2, 5]);
        let ids = [3, 2, params::coinbase_creation_id(2), 6, 2];
        let result = store.get_creation_headers(&ids).unwrap();
        assert_eq!(
            result
                .iter()
                .map(|h| h.as_ref().map(|h| h.height))
                .collect::<Vec<_>>(),
            [Some(3), Some(1), Some(2), None, Some(1)]
        );
        install([0, 1, 4, 5]);
        assert_eq!(
            store.get_creation_headers(&[2]).unwrap()[0]
                .as_ref()
                .unwrap()
                .height,
            2
        );
    }
}
