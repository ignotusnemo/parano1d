// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded branch graph for headers that already passed native validation.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use noid_chain::{
    add_work,
    block_header::{block_id, BlockHeader},
    block_work,
    consensus::fork_choice::{choose_chain_by_work, ChainChoice},
};
use noid_p2p::header_protocol::HeaderInventoryRecord;
use thiserror::Error;

use super::types::{ChainPoint, Hash32};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedHeader {
    pub header: BlockHeader,
    pub hash: Hash32,
    pub cumulative_work: Hash32,
}

impl ValidatedHeader {
    /// Construct only after the caller has run the complete native header
    /// checks for this exact ancestry.
    pub fn new_after_consensus_checks(header: BlockHeader, cumulative_work: Hash32) -> Self {
        Self {
            hash: block_id(&header),
            header,
            cumulative_work,
        }
    }

    pub const fn point(&self) -> ChainPoint {
        ChainPoint::new(self.header.height, self.hash)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderDagUpdate {
    Duplicate,
    Added,
    NewBest {
        previous: ChainPoint,
        best: ChainPoint,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderDagError {
    #[error("header is at or below the finalized boundary")]
    BelowFinalized,
    #[error("validated header parent is unknown")]
    MissingParent,
    #[error("validated header height does not follow its parent")]
    BadHeight,
    #[error("validated header cumulative work does not extend its parent")]
    BadCumulativeWork,
    #[error("header hash already identifies different data")]
    HashCollision,
    #[error("header DAG reached its configured capacity")]
    Capacity,
    #[error("requested header is unknown")]
    UnknownHeader,
    #[error("requested base is not an ancestor of the target")]
    NotAncestor,
    #[error("new finalized point is not on the current best ancestry")]
    FinalizedOffBestChain,
    #[error("object inventory refers to an unknown or different header")]
    InventoryHeaderMismatch,
    #[error("object inventory provider capacity is exhausted")]
    InventoryProviderCapacity,
}

/// The DAG does not validate State or commit chain data. It only retains
/// already native-validated headers and performs deterministic work ordering.
pub struct HeaderDag {
    finalized: ChainPoint,
    finalized_work: Hash32,
    best: ChainPoint,
    best_work: Hash32,
    nodes: HashMap<Hash32, ValidatedHeader>,
    /// Availability hints are deliberately subordinate to the validated DAG.
    /// They can select a byte source, never a branch or a cumulative-work view.
    inventories: HashMap<Hash32, HashMap<PeerId, HeaderInventoryRecord>>,
    max_nodes: usize,
}

impl HeaderDag {
    pub fn new(finalized: ChainPoint, finalized_work: Hash32, max_nodes: usize) -> Self {
        assert!(max_nodes > 0, "header DAG capacity must be non-zero");
        Self {
            finalized,
            finalized_work,
            best: finalized,
            best_work: finalized_work,
            nodes: HashMap::new(),
            inventories: HashMap::new(),
            max_nodes,
        }
    }

    pub const fn finalized(&self) -> ChainPoint {
        self.finalized
    }

    pub const fn finalized_work(&self) -> Hash32 {
        self.finalized_work
    }

    pub const fn best_tip(&self) -> ChainPoint {
        self.best
    }

    pub const fn best_work(&self) -> Hash32 {
        self.best_work
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, hash: &Hash32) -> Option<&ValidatedHeader> {
        self.nodes.get(hash)
    }

    /// Attach exact-object availability to headers which already passed the
    /// native consensus path. A peer can never introduce a header through this
    /// API and at most a bounded provider set is retained per header.
    pub fn advertise_inventory(
        &mut self,
        peer: PeerId,
        records: &[HeaderInventoryRecord],
    ) -> Result<usize, HeaderDagError> {
        const MAX_PROVIDERS_PER_HEADER: usize = 16;
        for record in records {
            let hash = block_id(&record.header);
            let Some(header) = self.nodes.get(&hash) else {
                return Err(HeaderDagError::InventoryHeaderMismatch);
            };
            if header.header != record.header {
                return Err(HeaderDagError::InventoryHeaderMismatch);
            }
            if self.inventories.get(&hash).is_some_and(|providers| {
                !providers.contains_key(&peer) && providers.len() >= MAX_PROVIDERS_PER_HEADER
            }) {
                return Err(HeaderDagError::InventoryProviderCapacity);
            }
        }
        let mut inserted = 0usize;
        for record in records {
            let hash = block_id(&record.header);
            let providers = self.inventories.entry(hash).or_default();
            if providers.insert(peer, *record) != Some(*record) {
                inserted = inserted.saturating_add(1);
            }
        }
        Ok(inserted)
    }

    /// Return one path-shaped inventory for a specific source. Missing
    /// objects stay explicit; callers may merge several peer views without
    /// pretending that any one peer owns the complete path.
    pub fn inventory_for_provider(
        &self,
        peer: PeerId,
        headers: &[ValidatedHeader],
    ) -> Vec<HeaderInventoryRecord> {
        headers
            .iter()
            .map(|header| {
                self.inventories
                    .get(&header.hash)
                    .and_then(|providers| providers.get(&peer))
                    .copied()
                    .unwrap_or_else(|| HeaderInventoryRecord::header_only(header.header))
            })
            .collect()
    }

    pub fn inventory_providers(&self, headers: &[ValidatedHeader]) -> Vec<PeerId> {
        let mut providers = headers
            .iter()
            .filter_map(|header| self.inventories.get(&header.hash))
            .flat_map(HashMap::keys)
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        providers.sort_by_key(|peer| peer.to_bytes());
        providers
    }

    /// Choose a provider for the exact terminal at one selected tip. The
    /// preferred peer wins only when it advertised that same validated tip.
    pub fn terminal_provider(
        &self,
        target: ChainPoint,
        preferred: Option<PeerId>,
    ) -> Option<(PeerId, noid_p2p::object_protocol::TerminalObjectId)> {
        let providers = self.inventories.get(&target.hash)?;
        let terminal = |peer: PeerId| {
            providers
                .get(&peer)
                .and_then(|record| record.terminal)
                .filter(|terminal| {
                    terminal.claim.height == target.height
                        && self.nodes.get(&target.hash).is_some_and(|header| {
                            terminal.claim.semantic_header_id
                                == noid_chain::block_header::semantic_header_id(&header.header)
                        })
                })
                .map(|terminal| (peer, terminal))
        };
        if let Some(preferred) = preferred.and_then(terminal) {
            return Some(preferred);
        }
        let mut peers = providers.keys().copied().collect::<Vec<_>>();
        peers.sort_by_key(|peer| peer.to_bytes());
        peers.into_iter().find_map(terminal)
    }

    pub fn remove_inventory_provider(&mut self, peer: PeerId) {
        self.inventories.retain(|_, providers| {
            providers.remove(&peer);
            !providers.is_empty()
        });
    }

    pub fn cumulative_work(&self, point: ChainPoint) -> Result<Hash32, HeaderDagError> {
        if point == self.finalized {
            return Ok(self.finalized_work);
        }
        let header = self
            .nodes
            .get(&point.hash)
            .ok_or(HeaderDagError::UnknownHeader)?;
        if header.header.height != point.height {
            return Err(HeaderDagError::UnknownHeader);
        }
        Ok(header.cumulative_work)
    }

    pub fn insert(
        &mut self,
        candidate: ValidatedHeader,
    ) -> Result<HeaderDagUpdate, HeaderDagError> {
        if candidate.header.height <= self.finalized.height {
            return Err(HeaderDagError::BelowFinalized);
        }
        if let Some(existing) = self.nodes.get(&candidate.hash) {
            return if existing == &candidate {
                Ok(HeaderDagUpdate::Duplicate)
            } else {
                Err(HeaderDagError::HashCollision)
            };
        }

        let (parent, parent_work) = if candidate.header.prev_block_hash == self.finalized.hash {
            (self.finalized, self.finalized_work)
        } else {
            let parent = self
                .nodes
                .get(&candidate.header.prev_block_hash)
                .ok_or(HeaderDagError::MissingParent)?;
            (parent.point(), parent.cumulative_work)
        };
        if candidate.header.height != parent.height.saturating_add(1) {
            return Err(HeaderDagError::BadHeight);
        }
        if candidate.cumulative_work
            != add_work(
                &parent_work,
                &block_work(&candidate.header.difficulty_target),
            )
        {
            return Err(HeaderDagError::BadCumulativeWork);
        }
        if self.nodes.len() >= self.max_nodes && !self.evict_unprotected_leaf(parent)? {
            return Err(HeaderDagError::Capacity);
        }

        let previous = self.best;
        let candidate_point = candidate.point();
        let candidate_work = candidate.cumulative_work;
        self.nodes.insert(candidate.hash, candidate);
        if matches!(
            choose_chain_by_work(
                &candidate_work,
                &candidate_point.hash,
                &self.best_work,
                &self.best.hash,
            ),
            ChainChoice::A
        ) {
            self.best = candidate_point;
            self.best_work = candidate_work;
            Ok(HeaderDagUpdate::NewBest {
                previous,
                best: self.best,
            })
        } else {
            Ok(HeaderDagUpdate::Added)
        }
    }

    /// Make room without breaking either the selected ancestry or the branch
    /// extended by the incoming header. A bounded DAG must not become
    /// permanently unusable after many valid losing siblings arrive.
    fn evict_unprotected_leaf(
        &mut self,
        candidate_parent: ChainPoint,
    ) -> Result<bool, HeaderDagError> {
        let mut protected = HashSet::new();
        self.collect_ancestry_hashes(self.best, &mut protected)?;
        self.collect_ancestry_hashes(candidate_parent, &mut protected)?;

        let parent_hashes = self
            .nodes
            .values()
            .map(|node| node.header.prev_block_hash)
            .collect::<HashSet<_>>();
        let mut eviction: Option<ValidatedHeader> = None;
        for node in
            self.nodes.values().copied().filter(|node| {
                !protected.contains(&node.hash) && !parent_hashes.contains(&node.hash)
            })
        {
            if eviction.is_none_or(|current| {
                matches!(
                    choose_chain_by_work(
                        &node.cumulative_work,
                        &node.hash,
                        &current.cumulative_work,
                        &current.hash,
                    ),
                    ChainChoice::B
                )
            }) {
                eviction = Some(node);
            }
        }

        let Some(eviction) = eviction else {
            return Ok(false);
        };
        self.nodes.remove(&eviction.hash);
        self.inventories.remove(&eviction.hash);
        Ok(true)
    }

    fn collect_ancestry_hashes(
        &self,
        mut point: ChainPoint,
        hashes: &mut HashSet<Hash32>,
    ) -> Result<(), HeaderDagError> {
        while point != self.finalized {
            hashes.insert(point.hash);
            point = self.parent(point)?;
        }
        Ok(())
    }

    pub fn path_from(
        &self,
        base: ChainPoint,
        target: ChainPoint,
    ) -> Result<Vec<ValidatedHeader>, HeaderDagError> {
        if base == target {
            return Ok(Vec::new());
        }
        let mut cursor = target;
        let mut reversed = Vec::new();
        while cursor != base {
            if cursor.height <= base.height {
                return Err(HeaderDagError::NotAncestor);
            }
            let node = self
                .nodes
                .get(&cursor.hash)
                .ok_or(HeaderDagError::UnknownHeader)?;
            reversed.push(*node);
            cursor = ChainPoint::new(
                node.header.height.saturating_sub(1),
                node.header.prev_block_hash,
            );
        }
        reversed.reverse();
        Ok(reversed)
    }

    /// Freeze the exact winning ancestry relative to the currently committed
    /// chain point. This is the only path a data-plane planner may turn into a
    /// live/reorg suffix.
    pub fn selected_path_from(
        &self,
        committed: ChainPoint,
    ) -> Result<(ChainPoint, Vec<ValidatedHeader>), HeaderDagError> {
        let ancestor = self.common_ancestor(committed, self.best)?;
        let path = self.path_from(ancestor, self.best)?;
        Ok((ancestor, path))
    }

    pub fn common_ancestor(
        &self,
        left: ChainPoint,
        right: ChainPoint,
    ) -> Result<ChainPoint, HeaderDagError> {
        let mut left = left;
        let mut right = right;
        while left.height > right.height {
            left = self.parent(left)?;
        }
        while right.height > left.height {
            right = self.parent(right)?;
        }
        while left != right {
            if left.height <= self.finalized.height || right.height <= self.finalized.height {
                return Err(HeaderDagError::NotAncestor);
            }
            left = self.parent(left)?;
            right = self.parent(right)?;
        }
        Ok(left)
    }

    pub fn is_ancestor(
        &self,
        ancestor: ChainPoint,
        descendant: ChainPoint,
    ) -> Result<bool, HeaderDagError> {
        if ancestor.height > descendant.height {
            return Ok(false);
        }
        let mut cursor = descendant;
        while cursor.height > ancestor.height {
            cursor = self.parent(cursor)?;
        }
        Ok(cursor == ancestor)
    }

    /// Return the exact point at `height` on `descendant`'s validated
    /// ancestry. Data-plane manifests may use this only after HeaderDAG has
    /// selected `descendant`; a peer-provided height/hash pair is never fork
    /// choice authority by itself.
    pub fn point_at_height(
        &self,
        descendant: ChainPoint,
        height: u64,
    ) -> Result<ChainPoint, HeaderDagError> {
        if height < self.finalized.height || height > descendant.height {
            return Err(HeaderDagError::NotAncestor);
        }
        let mut cursor = descendant;
        while cursor.height > height {
            cursor = self.parent(cursor)?;
        }
        Ok(cursor)
    }

    pub fn advance_finalized(
        &mut self,
        finalized: ChainPoint,
        finalized_work: Hash32,
    ) -> Result<(), HeaderDagError> {
        if finalized == self.finalized {
            self.finalized_work = finalized_work;
            return Ok(());
        }
        if !self.is_ancestor(finalized, self.best)? {
            return Err(HeaderDagError::FinalizedOffBestChain);
        }

        let mut keep = HashSet::new();
        for point in self
            .nodes
            .values()
            .map(ValidatedHeader::point)
            .filter(|point| point.height > finalized.height)
        {
            if self.is_ancestor(finalized, point).unwrap_or(false) {
                keep.insert(point.hash);
            }
        }
        self.nodes.retain(|hash, _| keep.contains(hash));
        self.inventories.retain(|hash, _| keep.contains(hash));
        self.finalized = finalized;
        self.finalized_work = finalized_work;
        if self.best.height <= finalized.height {
            self.best = finalized;
            self.best_work = finalized_work;
        }
        Ok(())
    }

    fn parent(&self, point: ChainPoint) -> Result<ChainPoint, HeaderDagError> {
        if point == self.finalized {
            return Err(HeaderDagError::NotAncestor);
        }
        let node = self
            .nodes
            .get(&point.hash)
            .ok_or(HeaderDagError::UnknownHeader)?;
        let parent = ChainPoint::new(
            node.header.height.saturating_sub(1),
            node.header.prev_block_hash,
        );
        if parent.height < self.finalized.height {
            return Err(HeaderDagError::NotAncestor);
        }
        if parent.height == self.finalized.height && parent != self.finalized {
            return Err(HeaderDagError::NotAncestor);
        }
        Ok(parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::genesis_header;
    use noid_p2p::{
        header_protocol::HeaderInventoryRecord,
        object_protocol::{BlockBodyClaimId, BlockBodyObjectId, TerminalClaimId, TerminalObjectId},
    };

    fn child(parent: BlockHeader, parent_work: Hash32, nonce: u128) -> ValidatedHeader {
        let mut header = parent;
        header.prev_block_hash = block_id(&parent);
        header.height = parent.height + 1;
        header.timestamp += 1;
        header.nonce = nonce;
        let cumulative_work = add_work(&parent_work, &block_work(&header.difficulty_target));
        ValidatedHeader::new_after_consensus_checks(header, cumulative_work)
    }

    fn inventory(header: ValidatedHeader, marker: u8, terminal: bool) -> HeaderInventoryRecord {
        HeaderInventoryRecord {
            header: header.header,
            body: Some(BlockBodyObjectId {
                claim: BlockBodyClaimId {
                    height: header.header.height,
                    block_hash: header.hash,
                },
                byte_digest: [marker; 32],
                encoded_len: 1,
            }),
            terminal: terminal.then_some(TerminalObjectId {
                claim: TerminalClaimId {
                    height: header.header.height,
                    semantic_header_id: noid_chain::block_header::semantic_header_id(
                        &header.header,
                    ),
                    proof_class: 0,
                },
                byte_digest: [marker.wrapping_add(1); 32],
                encoded_len: 2,
            }),
        }
    }

    #[test]
    fn best_tip_uses_work_and_exact_hash_tie_break() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 16);
        let left = child(genesis, [1; 32], 1);
        let right = child(genesis, [1; 32], 2);
        let (a, b) = if matches!(
            choose_chain_by_work(
                &left.cumulative_work,
                &left.hash,
                &right.cumulative_work,
                &right.hash,
            ),
            ChainChoice::A
        ) {
            (right, left)
        } else {
            (left, right)
        };

        assert!(matches!(
            dag.insert(a).unwrap(),
            HeaderDagUpdate::NewBest { .. }
        ));
        assert!(matches!(
            dag.insert(b).unwrap(),
            HeaderDagUpdate::NewBest { best, .. } if best == b.point()
        ));
        assert_eq!(dag.best_tip(), b.point());
    }

    #[test]
    fn exact_paths_and_common_ancestor_are_source_independent() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 16);
        let a1 = child(genesis, [1; 32], 1);
        let a2 = child(a1.header, a1.cumulative_work, 2);
        let b2 = child(a1.header, a1.cumulative_work, 3);
        dag.insert(a1).unwrap();
        dag.insert(a2).unwrap();
        dag.insert(b2).unwrap();

        assert_eq!(
            dag.common_ancestor(a2.point(), b2.point()).unwrap(),
            a1.point()
        );
        assert_eq!(dag.path_from(a1.point(), b2.point()).unwrap(), vec![b2]);
    }

    #[test]
    fn selected_path_is_independent_of_peer_branch_arrival_order() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let a1 = child(genesis, [1; 32], 1);
        let a2 = child(a1.header, a1.cumulative_work, 2);
        let b1 = child(genesis, [1; 32], 3);
        let b2 = child(b1.header, b1.cumulative_work, 4);
        let b3 = child(b2.header, b2.cumulative_work, 5);

        let mut left_first = HeaderDag::new(finalized, [1; 32], 16);
        for header in [a1, a2, b1, b2, b3] {
            left_first.insert(header).unwrap();
        }

        let mut right_first = HeaderDag::new(finalized, [1; 32], 16);
        for header in [b1, b2, b3, a1, a2] {
            right_first.insert(header).unwrap();
        }

        assert_eq!(left_first.best_tip(), right_first.best_tip());
        assert_eq!(
            left_first.selected_path_from(finalized).unwrap(),
            right_first.selected_path_from(finalized).unwrap()
        );
    }

    #[test]
    fn point_at_height_binds_data_to_the_selected_ancestry() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 16);
        let first = child(genesis, [1; 32], 1);
        let second = child(first.header, first.cumulative_work, 2);
        dag.insert(first).unwrap();
        dag.insert(second).unwrap();

        assert_eq!(
            dag.point_at_height(second.point(), first.header.height)
                .unwrap(),
            first.point()
        );
        assert_eq!(
            dag.point_at_height(second.point(), finalized.height)
                .unwrap(),
            finalized
        );
        assert_eq!(
            dag.point_at_height(first.point(), second.header.height),
            Err(HeaderDagError::NotAncestor)
        );
    }

    #[test]
    fn inventories_merge_sources_without_changing_header_authority() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 16);
        let first = child(genesis, [1; 32], 1);
        let second = child(first.header, first.cumulative_work, 2);
        dag.insert(first).unwrap();
        dag.insert(second).unwrap();

        let body_peer = PeerId::random();
        let terminal_peer = PeerId::random();
        dag.advertise_inventory(body_peer, &[inventory(first, 1, false)])
            .unwrap();
        dag.advertise_inventory(terminal_peer, &[inventory(second, 2, true)])
            .unwrap();

        let path = [first, second];
        let body_view = dag.inventory_for_provider(body_peer, &path);
        let terminal_view = dag.inventory_for_provider(terminal_peer, &path);
        assert!(body_view[0].body.is_some());
        assert!(body_view[1].body.is_none());
        assert!(terminal_view[0].body.is_none());
        assert!(terminal_view[1].terminal.is_some());
        assert_eq!(
            dag.terminal_provider(second.point(), Some(body_peer))
                .map(|(peer, _)| peer),
            Some(terminal_peer)
        );
        assert_eq!(dag.best_tip(), second.point());

        dag.remove_inventory_provider(terminal_peer);
        assert!(dag.terminal_provider(second.point(), None).is_none());
    }

    #[test]
    fn missing_parent_and_capacity_fail_without_mutation() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 1);
        let a = child(genesis, [1; 32], 1);
        let mut orphan = child(a.header, a.cumulative_work, 2);
        orphan.header.prev_block_hash = [9; 32];
        orphan.hash = block_id(&orphan.header);
        assert_eq!(dag.insert(orphan), Err(HeaderDagError::MissingParent));
        assert_eq!(dag.len(), 0);
        dag.insert(a).unwrap();
        let b = child(genesis, [1; 32], 4);
        assert_eq!(dag.insert(b), Err(HeaderDagError::Capacity));
        assert_eq!(dag.len(), 1);
    }

    #[test]
    fn malformed_cached_work_is_rejected_before_insertion() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 4);
        let mut candidate = child(genesis, [1; 32], 1);
        candidate.cumulative_work[0] ^= 1;
        assert_eq!(
            dag.insert(candidate),
            Err(HeaderDagError::BadCumulativeWork)
        );
        assert!(dag.is_empty());
    }

    #[test]
    fn full_sibling_set_cannot_block_the_selected_chain_extension() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 4);
        for nonce in 1..=4 {
            dag.insert(child(genesis, [1; 32], nonce)).unwrap();
        }
        let selected = dag.best_tip();
        let selected_header = dag.get(&selected.hash).copied().unwrap();
        let mut invalid = child(selected_header.header, selected_header.cumulative_work, 5);
        invalid.cumulative_work[0] ^= 1;
        assert_eq!(dag.insert(invalid), Err(HeaderDagError::BadCumulativeWork));
        assert_eq!(dag.len(), 4);

        let extension = child(selected_header.header, selected_header.cumulative_work, 5);

        assert!(matches!(
            dag.insert(extension).unwrap(),
            HeaderDagUpdate::NewBest { best, .. } if best == extension.point()
        ));
        assert_eq!(dag.len(), 4);
        assert!(dag.get(&selected.hash).is_some());
        assert!(dag.get(&extension.hash).is_some());
    }
}
