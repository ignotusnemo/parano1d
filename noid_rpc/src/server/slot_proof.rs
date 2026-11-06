// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded, read-only exact-state proofs for external wallets.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use noid_chain::exact_state_hash::slot_leaf_hash;
use noid_chain::fri_state::SlotValue;
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::sparse_merkle::reconstruct_root;
use noid_chain::state::ChainState;
use noid_chain::storage::MdbxChainContext;
use noid_chain::BlockHeader;
use noid_poseidon2b::primitives::Address;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::types::{SlotInfo, SlotProofInfo, SLOT_PROOF_MAX_INDICES, SLOT_PROOF_MAX_SEGMENTS};

// A query may temporarily hydrate eight 3 MiB segments and use the existing
// bounded Merkle-tree cache. Keep one such worker across all RPC listeners.
static SERVING: OnceLock<Arc<Semaphore>> = OnceLock::new();

pub(super) fn acquire() -> Result<OwnedSemaphorePermit, String> {
    Arc::clone(SERVING.get_or_init(|| Arc::new(Semaphore::new(1))))
        .try_acquire_owned()
        .map_err(|_| "Merkle proof service is busy; retry the request".into())
}

pub(super) fn validate_indices(indices: &[u32]) -> Result<(), String> {
    if indices.is_empty() || indices.len() > SLOT_PROOF_MAX_INDICES {
        return Err(format!(
            "slot proof requires 1..={SLOT_PROOF_MAX_INDICES} indices"
        ));
    }
    if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("slot proof indices must be sorted and unique".into());
    }
    Ok(())
}

pub(super) fn build(chain: &MdbxChainContext, indices: &[u32]) -> Result<SlotProofInfo, String> {
    build_view(&chain.state, chain.tip_header(), indices, |id| {
        chain
            .store
            .get_segment(id)
            .map_err(|error| error.to_string())
    })
}

fn build_view(
    state: &ChainState,
    header: &BlockHeader,
    indices: &[u32],
    mut load: impl FnMut(u16) -> Result<Option<(u8, SegmentColumns)>, String>,
) -> Result<SlotProofInfo, String> {
    validate_indices(indices)?;
    let depth = header.log_slots;
    if depth > 32
        || state.state.log_slots() != depth as usize
        || state.cached_state_root() != header.state_root
    {
        return Err("slot proof chain boundary mismatch".into());
    }
    if indices
        .iter()
        .any(|&index| u64::from(index) >= 1u64 << depth)
    {
        return Err("slot proof index is outside the current slot domain".into());
    }
    let segment_log = state.state.effective_log_segment_size();
    let segments: BTreeSet<_> = indices
        .iter()
        .map(|index| (index >> segment_log) as u16)
        .collect();
    if segments.len() > SLOT_PROOF_MAX_SEGMENTS {
        return Err(format!(
            "slot proof spans more than {SLOT_PROOF_MAX_SEGMENTS} segments"
        ));
    }

    // Raw resident columns and cached trees are immutable Arc versions.
    // Only cold segments needed for this bounded query are restored locally.
    let mut view = state.clone();
    for id in segments {
        if !view.state.is_evicted(id) {
            continue;
        }
        let (stored_log, columns) =
            load(id)?.ok_or_else(|| format!("slot proof segment {id} is unavailable"))?;
        if usize::from(stored_log) != segment_log {
            return Err(format!("slot proof segment {id} has a different depth"));
        }
        view.restore_evicted_segment(id, columns)
            .map_err(|error| error.to_string())?;
    }
    let values: Vec<_> = indices
        .iter()
        .map(|&index| view.state.slot(index))
        .collect();
    let leaves: Vec<_> = values.iter().copied().map(slot_leaf_hash).collect();
    let siblings = view
        .exact_frontier_siblings(indices, depth)
        .map_err(|error| error.to_string())?;
    if reconstruct_root(indices, &leaves, &siblings, depth).map_err(|error| error.to_string())?
        != header.state_root
    {
        return Err("slot proof does not reconstruct its canonical State root".into());
    }
    let slots = indices
        .iter()
        .zip(values)
        .map(|(&slot_index, slot)| {
            let empty = slot == SlotValue::EMPTY;
            let mut owner = [0u8; 32];
            owner[..16].copy_from_slice(&slot.owner_hi.0.to_le_bytes());
            owner[16..].copy_from_slice(&slot.owner_lo.0.to_le_bytes());
            SlotInfo {
                slot_index,
                value: slot.amount(),
                creation_id: slot.creation_id(),
                owner: if empty {
                    String::new()
                } else {
                    Address(owner).to_bech32()
                },
                empty,
            }
        })
        .collect();
    Ok(SlotProofInfo {
        height: header.height,
        block_hash: hex::encode(super::block_id(header)),
        state_root: hex::encode(header.state_root),
        log_slots: depth,
        slots,
        siblings: siblings.iter().map(hex::encode).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::{genesis_header, params};
    use noid_tx::native_assets::NATIVE_CREATION_TAG;

    fn fixture() -> (ChainState, BlockHeader) {
        let owner = Address(std::array::from_fn(|i| (i + 1) as u8));
        let slots = [
            (2, SlotValue::with_owner_fields(41, 1, owner.as_fields())),
            (
                9,
                SlotValue::with_owner_fields(
                    0,
                    NATIVE_CREATION_TAG | 2,
                    Address([7; 32]).as_fields(),
                ),
            ),
        ];
        let activation = params::V2_1_ACTIVATION_HEIGHT.expect("scheduled native activation");
        let state = ChainState::from_sparse_utxos_at(4, &slots, 2, activation).unwrap();
        let mut header = genesis_header();
        header.height = activation;
        header.log_slots = 4;
        header.alloc_counter = 2;
        header.active_slot_count = 2;
        header.state_root = state.cached_state_root();
        (state, header)
    }

    fn reconstructed(
        proof: &SlotProofInfo,
    ) -> Result<[u8; 32], noid_chain::sparse_merkle::SparseMerkleError> {
        let indices: Vec<_> = proof.slots.iter().map(|slot| slot.slot_index).collect();
        let leaves: Vec<_> = proof
            .slots
            .iter()
            .map(|slot| {
                let owner = if slot.empty {
                    Address([0; 32])
                } else {
                    Address::parse(&slot.owner).unwrap()
                };
                slot_leaf_hash(SlotValue::with_owner_fields(
                    slot.value,
                    slot.creation_id,
                    owner.as_fields(),
                ))
            })
            .collect();
        let siblings: Vec<[u8; 32]> = proof
            .siblings
            .iter()
            .map(|s| hex::decode(s).unwrap().try_into().unwrap())
            .collect();
        reconstruct_root(&indices, &leaves, &siblings, proof.log_slots)
    }

    #[test]
    fn slot_proof_wire_authenticates_live_empty_and_native_slots() {
        let (state, header) = fixture();
        let proof = build_view(&state, &header, &[2, 3, 9], |_| {
            panic!("resident query performed IO")
        })
        .unwrap();
        let proof: SlotProofInfo =
            serde_json::from_value(serde_json::to_value(proof).unwrap()).unwrap();
        assert_eq!(reconstructed(&proof).unwrap(), header.state_root);
        assert_eq!(
            proof.block_hash,
            hex::encode(super::super::block_id(&header))
        );
        assert!(proof.slots[1].empty);
        assert!(!proof.slots[2].empty);
        assert_eq!(proof.slots[2].value, 0);
        for field in 0..5 {
            let mut tampered = proof.clone();
            match field {
                0 => tampered.slots[0].value += 1,
                1 => tampered.slots[0].creation_id += 1,
                2 => tampered.slots[0].owner = Address([4; 32]).to_bech32(),
                3 => tampered.slots[0].slot_index = 1,
                _ => {
                    let mut sibling = hex::decode(&tampered.siblings[0]).unwrap();
                    sibling[0] ^= 1;
                    tampered.siblings[0] = hex::encode(sibling);
                }
            }
            assert_ne!(reconstructed(&tampered).ok(), Some(header.state_root));
        }
    }

    #[test]
    fn slot_proof_restores_only_a_local_copy_and_rejects_corrupt_cold_data() {
        let (mut state, header) = fixture();
        let columns = state.state.try_get_segment_columns(0).unwrap().clone();
        state.state.evict_segment(0);
        let proof = build_view(&state, &header, &[2, 3], |id| {
            assert_eq!(id, 0);
            Ok(Some((4, columns.clone())))
        })
        .unwrap();
        assert_eq!(reconstructed(&proof).unwrap(), header.state_root);
        assert!(state.state.is_evicted(0));
        let mut corrupt = columns.clone();
        corrupt.values[2].0 ^= 1;
        assert!(build_view(&state, &header, &[2], |_| Ok(Some((4, corrupt.clone())))).is_err());
        assert!(build_view(&state, &header, &[2], |_| Ok(None)).is_err());
        assert!(build_view(&state, &header, &[2], |_| Ok(Some((3, columns.clone())))).is_err());
    }

    #[test]
    fn slot_proof_rejects_noncanonical_oversized_and_mismatched_requests() {
        let (state, mut header) = fixture();
        for indices in [vec![], vec![2, 2], vec![3, 2], vec![16], (0..129).collect()] {
            assert!(build_view(&state, &header, &indices, |_| panic!(
                "invalid query performed IO"
            ))
            .is_err());
        }
        header.state_root[0] ^= 1;
        assert!(build_view(&state, &header, &[2], |_| panic!(
            "mismatched query performed IO"
        ))
        .is_err());
        let state = ChainState::from_sparse_utxos(20, &[], 0).unwrap();
        header.log_slots = 20;
        header.state_root = state.cached_state_root();
        let indices: Vec<_> = (0..9).map(|id| id << 16).collect();
        assert!(build_view(&state, &header, &indices, |_| panic!(
            "oversized query performed IO"
        ))
        .is_err());
    }

    #[test]
    fn slot_proof_service_rejects_an_overlapping_worker() {
        let permit = acquire().unwrap();
        assert!(acquire().is_err());
        drop(permit);
        assert!(acquire().is_ok());
    }
}
