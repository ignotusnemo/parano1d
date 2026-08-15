// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mining readiness without conflating connectivity and ancestry authority.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;

use super::types::{ChainPoint, FailureDomain};

#[derive(Clone, Copy, Debug)]
struct HealthLease {
    failure_domain: FailureDomain,
    expires_at_ms: u64,
    compatible: bool,
    blocks_mining: bool,
}

#[derive(Clone, Copy, Debug)]
struct FrontierLease {
    authorized_parent: ChainPoint,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MiningReadinessSnapshot {
    pub authenticated_leases: usize,
    pub healthy_failure_domains: usize,
    pub frontier_authorizations: usize,
    pub network_health_ready: bool,
    pub proof_build_ready: bool,
    pub nonce_search_ready: bool,
}

/// Two deliberately separate permissions:
///
/// - network health is stable across ordinary tip advances;
/// - frontier authorization follows a validated canonical ancestry and is
///   revoked on branch replacement.
pub struct MiningReadiness {
    isolated: bool,
    required_failure_domains: usize,
    initial_sync_complete: bool,
    unresolved_better_header: bool,
    committed_tip: ChainPoint,
    template_parent: ChainPoint,
    health: HashMap<PeerId, HealthLease>,
    frontier: HashMap<PeerId, FrontierLease>,
}

impl MiningReadiness {
    pub fn new(isolated: bool, required_failure_domains: usize, committed_tip: ChainPoint) -> Self {
        assert!(
            isolated || required_failure_domains > 0,
            "network mining must require at least one failure domain"
        );
        Self {
            isolated,
            required_failure_domains,
            initial_sync_complete: isolated,
            unresolved_better_header: false,
            committed_tip,
            template_parent: committed_tip,
            health: HashMap::new(),
            frontier: HashMap::new(),
        }
    }

    pub fn set_sync_state(&mut self, complete: bool, unresolved_better_header: bool) {
        self.initial_sync_complete = complete;
        self.unresolved_better_header = unresolved_better_header;
    }

    /// A normal canonical child preserves the network view which authorized
    /// its parent. A branch replacement revokes it. This matches ordinary
    /// node mining: a locally accepted child does not require a peer to echo
    /// the new hash before nonce search may continue.
    pub fn set_committed_tip(&mut self, tip: ChainPoint, extends_previous: bool) {
        if extends_previous {
            let previous_parent = self.template_parent;
            self.frontier.retain(|_, lease| {
                if lease.authorized_parent == previous_parent {
                    lease.authorized_parent = tip;
                    true
                } else {
                    false
                }
            });
        } else {
            self.frontier.clear();
        }
        self.committed_tip = tip;
        self.template_parent = tip;
    }

    /// Renew one authenticated peer's stable chain-view lease.
    ///
    /// `compatible` means its finalized/view information is consistent with
    /// the locally validated ancestry. `blocks_mining` means the observation
    /// exposes a stronger or incompatible branch that still needs resolution.
    pub fn renew_health(
        &mut self,
        peer: PeerId,
        failure_domain: FailureDomain,
        expires_at_ms: u64,
        compatible: bool,
        blocks_mining: bool,
    ) {
        self.health.insert(
            peer,
            HealthLease {
                failure_domain,
                expires_at_ms,
                compatible,
                blocks_mining,
            },
        );
        if !compatible || blocks_mining {
            self.frontier.remove(&peer);
        }
    }

    /// Resolve every compatible chain-view observation against the exact
    /// canonical tip that has just committed.
    ///
    /// Several peers may announce the same stronger tip before its objects
    /// are verified.  They all temporarily block mining.  Once the committer
    /// has installed that exact HeaderDAG-selected tip, those compatible
    /// observations no longer represent unresolved work.  Incompatible
    /// observations remain blocking and frontier authority is still granted
    /// separately to peers that supplied an exact object for the committed
    /// tip.
    pub fn resolve_committed_view(&mut self) {
        for lease in self.health.values_mut() {
            if lease.compatible {
                lease.blocks_mining = false;
            }
        }
    }

    /// Record a peer report that natively authorizes the exact current
    /// template parent. A later ordinary child may retain this lease because
    /// the committer has established that the point remains in the canonical
    /// ancestry.
    pub fn authorize_frontier(
        &mut self,
        peer: PeerId,
        parent: ChainPoint,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> bool {
        if parent != self.template_parent {
            return false;
        }
        let Some(health) = self.health.get(&peer) else {
            return false;
        };
        if health.expires_at_ms <= now_ms || !health.compatible || health.blocks_mining {
            return false;
        }
        self.frontier.insert(
            peer,
            FrontierLease {
                authorized_parent: parent,
                expires_at_ms: expires_at_ms.min(health.expires_at_ms),
            },
        );
        true
    }

    pub fn disconnect(&mut self, peer: PeerId) {
        self.health.remove(&peer);
        self.frontier.remove(&peer);
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.health.retain(|_, lease| lease.expires_at_ms > now_ms);
        self.frontier
            .retain(|peer, lease| lease.expires_at_ms > now_ms && self.health.contains_key(peer));
    }

    pub fn snapshot(&self, now_ms: u64) -> MiningReadinessSnapshot {
        if self.isolated {
            return MiningReadinessSnapshot {
                network_health_ready: true,
                proof_build_ready: true,
                nonce_search_ready: true,
                ..MiningReadinessSnapshot::default()
            };
        }

        let live_health = self
            .health
            .iter()
            .filter(|(_, lease)| {
                lease.expires_at_ms > now_ms && lease.compatible && !lease.blocks_mining
            })
            .collect::<Vec<_>>();
        let healthy_domains = live_health
            .iter()
            .map(|(_, lease)| lease.failure_domain)
            .collect::<HashSet<_>>();
        let frontier_domains = live_health
            .iter()
            .filter_map(|(peer, health)| {
                self.frontier.get(peer).and_then(|lease| {
                    (lease.expires_at_ms > now_ms
                        && lease.authorized_parent == self.template_parent)
                        .then_some(health.failure_domain)
                })
            })
            .collect::<HashSet<_>>();
        let network_health_ready = healthy_domains.len() >= self.required_failure_domains;
        let proof_build_ready = self.initial_sync_complete
            && !self.unresolved_better_header
            && self.template_parent == self.committed_tip
            && !self
                .health
                .values()
                .any(|lease| lease.expires_at_ms > now_ms && lease.blocks_mining);
        let nonce_search_ready = proof_build_ready
            && network_health_ready
            && frontier_domains.len() >= self.required_failure_domains;

        MiningReadinessSnapshot {
            authenticated_leases: live_health.len(),
            healthy_failure_domains: healthy_domains.len(),
            frontier_authorizations: frontier_domains.len(),
            network_health_ready,
            proof_build_ready,
            nonce_search_ready,
        }
    }

    pub const fn committed_tip(&self) -> ChainPoint {
        self.committed_tip
    }

    pub const fn template_parent(&self) -> ChainPoint {
        self.template_parent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(height: u64) -> ChainPoint {
        ChainPoint::new(height, [height as u8; 32])
    }

    fn ready_fixture() -> (MiningReadiness, PeerId, PeerId) {
        let mut readiness = MiningReadiness::new(false, 2, point(10));
        readiness.set_sync_state(true, false);
        let first = PeerId::random();
        let second = PeerId::random();
        readiness.renew_health(first, FailureDomain(1), 100, true, false);
        readiness.renew_health(second, FailureDomain(2), 100, true, false);
        assert!(readiness.authorize_frontier(first, point(10), 100, 0));
        assert!(readiness.authorize_frontier(second, point(10), 100, 0));
        (readiness, first, second)
    }

    #[test]
    fn ordinary_canonical_child_preserves_mining_authorization() {
        let (mut readiness, first, second) = ready_fixture();
        assert!(readiness.snapshot(0).nonce_search_ready);

        readiness.set_committed_tip(point(11), true);
        let after_commit = readiness.snapshot(0);
        assert!(after_commit.network_health_ready);
        assert!(after_commit.proof_build_ready);
        assert_eq!(after_commit.frontier_authorizations, 2);
        assert!(after_commit.nonce_search_ready);
        assert!(!readiness.authorize_frontier(first, point(10), 100, 0));
        assert!(!readiness.authorize_frontier(second, point(10), 100, 0));
    }

    #[test]
    fn branch_replacement_revokes_old_ancestry_authority() {
        let (mut readiness, first, second) = ready_fixture();
        readiness.set_committed_tip(point(11), false);
        assert!(!readiness.authorize_frontier(first, point(10), 100, 0));
        assert!(!readiness.authorize_frontier(second, point(10), 100, 0));
        assert!(!readiness.snapshot(0).nonce_search_ready);
    }

    #[test]
    fn peer_ids_in_one_failure_domain_count_once() {
        let mut readiness = MiningReadiness::new(false, 2, point(1));
        readiness.set_sync_state(true, false);
        for _ in 0..4 {
            let peer = PeerId::random();
            readiness.renew_health(peer, FailureDomain(7), 100, true, false);
            readiness.authorize_frontier(peer, point(1), 100, 0);
        }
        let snapshot = readiness.snapshot(0);
        assert_eq!(snapshot.authenticated_leases, 4);
        assert_eq!(snapshot.healthy_failure_domains, 1);
        assert!(!snapshot.network_health_ready);
        assert!(!snapshot.nonce_search_ready);
    }

    #[test]
    fn expiry_and_disconnect_revoke_only_their_leases() {
        let (mut readiness, first, second) = ready_fixture();
        readiness.disconnect(first);
        let one_left = readiness.snapshot(0);
        assert_eq!(one_left.authenticated_leases, 1);
        assert!(!one_left.network_health_ready);

        readiness.expire(100);
        assert_eq!(readiness.snapshot(100).authenticated_leases, 0);
        readiness.disconnect(second);
    }

    #[test]
    fn unresolved_better_branch_pauses_proving_and_nonce_search() {
        let (mut readiness, _, _) = ready_fixture();
        readiness.set_sync_state(true, true);
        let snapshot = readiness.snapshot(0);
        assert!(snapshot.network_health_ready);
        assert!(!snapshot.proof_build_ready);
        assert!(!snapshot.nonce_search_ready);
    }

    #[test]
    fn exact_commit_resolves_all_compatible_announcers() {
        let (mut readiness, first, second) = ready_fixture();
        readiness.renew_health(first, FailureDomain(1), 100, true, true);
        readiness.renew_health(second, FailureDomain(2), 100, true, true);
        readiness.set_sync_state(true, true);
        assert!(!readiness.snapshot(0).proof_build_ready);

        readiness.set_committed_tip(point(11), true);
        readiness.set_sync_state(true, false);
        readiness.resolve_committed_view();

        let resolved = readiness.snapshot(0);
        assert!(resolved.network_health_ready);
        assert!(resolved.proof_build_ready);
        assert!(!resolved.nonce_search_ready);
        assert!(readiness.authorize_frontier(first, point(11), 100, 0));
        assert!(readiness.authorize_frontier(second, point(11), 100, 0));
        assert!(readiness.snapshot(0).nonce_search_ready);
    }
}
