// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Automatic background-service budgets.
//!
//! These are not network roles. Every process remains the same full node and
//! may verify, fetch and serve every object. The profile only reserves local
//! resources when block production is active.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundCapacity {
    /// Wallet/full-node mode: use the complete bounded background budget.
    Full,
    /// Mining mode: keep serving, but reserve CPU, memory and sockets for
    /// proving, PoW and timely chain processing.
    MiningReserved,
}

impl BackgroundCapacity {
    /// Header batches are small control-plane objects. Ordinary wallet/full
    /// nodes can serve more neighbours concurrently, while miners retain a
    /// smaller but mesh-complete allowance beside proof construction.
    pub(crate) const fn header_response_prepare_slots(self) -> usize {
        match self {
            Self::Full => 8,
            Self::MiningReserved => 4,
        }
    }

    pub(crate) const fn global_data_slots(self) -> usize {
        match self {
            Self::Full => 8,
            // A miner is the first complete source for its newly accepted
            // body and terminal. Snapshot work remains reduced below, but
            // live propagation must not be throttled to three streams while
            // dozens of followers are waiting for the same tip.
            Self::MiningReserved => 8,
        }
    }

    pub(crate) const fn per_peer_data_slots(self) -> usize {
        match self {
            Self::Full => 2,
            Self::MiningReserved => 1,
        }
    }

    pub(crate) const fn global_data_outstanding(self) -> usize {
        match self {
            Self::Full => 64,
            Self::MiningReserved => 32,
        }
    }

    /// Keep recent body/terminal serving deliberately shallow.  A deep live
    /// FIFO hides overload from requesters: dozens of nodes can believe that
    /// the same producer is making progress while only a few terminal streams
    /// are actually active.  Two waves are enough to absorb short scheduling
    /// jitter; later callers receive Busy and can use newly discovered exact
    /// providers instead of waiting behind the complete fan-in.
    pub(crate) const fn live_data_outstanding(self) -> usize {
        match self {
            Self::Full => 12,
            // MiningReserved has one State slot, leaving seven active Live
            // slots. Keep exactly two waves and return Busy after that.
            Self::MiningReserved => 14,
        }
    }

    pub(crate) const fn per_peer_data_outstanding(self) -> usize {
        match self {
            Self::Full => 4,
            Self::MiningReserved => 2,
        }
    }

    /// State snapshots are the heaviest and longest-lived data jobs. Keep
    /// them below the global data budget so bodies and recursive terminals
    /// always retain serving capacity during a cold-sync wave.
    pub(crate) const fn state_data_slots(self) -> usize {
        match self {
            Self::Full => 2,
            Self::MiningReserved => 1,
        }
    }

    /// Do not hide State saturation behind a server-side FIFO. A request that
    /// cannot enter one of the active State slots must receive Busy so the
    /// immutable client plan can use another provider or retry with backoff.
    pub(crate) const fn state_data_outstanding(self) -> usize {
        match self {
            Self::Full => 2,
            Self::MiningReserved => 1,
        }
    }

    /// Descriptor pages are small but must continue moving while long State
    /// segment streams occupy the ordinary snapshot lanes. This independent
    /// one-slot reserve never borrows the Live body/terminal budget.
    pub(crate) const fn state_metadata_slots(self) -> usize {
        1
    }

    pub(crate) const fn state_metadata_outstanding(self) -> usize {
        match self {
            Self::Full => 8,
            Self::MiningReserved => 4,
        }
    }

    pub(crate) const fn relay_max_reservations(self) -> usize {
        match self {
            // The swarm accepts at most 128 inbound connections. A public
            // full node may devote half to bounded relay reachability while
            // retaining 64 direct slots. Miners contribute less relay
            // capacity so proving and live-object propagation stay primary.
            Self::Full => 64,
            Self::MiningReserved => 32,
        }
    }

    pub(crate) const fn relay_max_circuits(self) -> usize {
        match self {
            Self::Full => 64,
            Self::MiningReserved => 16,
        }
    }

    pub(crate) const fn relay_max_circuits_per_peer(self) -> usize {
        match self {
            Self::Full => 2,
            Self::MiningReserved => 1,
        }
    }
}

/// libp2p-relay 0.18 checks the *existing* per-peer count with `>` before
/// inserting the next reservation/circuit. Its per-peer configuration value
/// is therefore one below the effective maximum (unlike the global fields,
/// which correctly use `>=`). Keep this compatibility rule in one tested
/// place until the pinned dependency changes its comparison.
pub(crate) const fn relay_018_per_peer_config(effective_maximum: usize) -> usize {
    effective_maximum.saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::{relay_018_per_peer_config, BackgroundCapacity};

    #[test]
    fn mining_prioritizes_live_propagation_and_reduces_background_work() {
        let full = BackgroundCapacity::Full;
        let mining = BackgroundCapacity::MiningReserved;
        assert_eq!(mining.global_data_slots(), full.global_data_slots());
        assert_eq!(
            mining.global_data_outstanding() * 2,
            full.global_data_outstanding()
        );
        assert!(mining.live_data_outstanding() > full.live_data_outstanding());
        assert_eq!(full.header_response_prepare_slots(), 8);
        assert_eq!(mining.header_response_prepare_slots(), 4);
        assert_eq!(
            mining.relay_max_reservations() * 2,
            full.relay_max_reservations()
        );
        assert_eq!(full.relay_max_reservations(), 64);
        assert_eq!(full.relay_max_circuits(), 64);
        assert_eq!(mining.relay_max_circuits(), 16);
        assert_eq!(mining.state_data_slots() * 2, full.state_data_slots());
        assert_eq!(
            mining.state_data_outstanding() * 2,
            full.state_data_outstanding()
        );
        assert_eq!(mining.state_metadata_slots(), 1);
        assert_eq!(
            mining.state_metadata_outstanding() * 2,
            full.state_metadata_outstanding()
        );
        assert!(full.state_data_slots() < full.global_data_slots());
        assert!(mining.per_peer_data_slots() > 0);
        assert!(mining.relay_max_circuits() > 0);
    }

    #[test]
    fn pinned_relay_per_peer_limits_compensate_upstream_off_by_one() {
        assert_eq!(relay_018_per_peer_config(1), 0);
        assert_eq!(relay_018_per_peer_config(2), 1);
        assert_eq!(relay_018_per_peer_config(0), 0);
    }
}
