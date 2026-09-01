// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Dynamic fee floor: tracks recent admitted-tx fees and raises the minimum.
//!
//! The floor is computed from recent admitted fees:
//!   `floor = max(MIN_FEE_BASE, median(last N fees) × 0.9)`
//!
//! This makes the floor self-calibrating: when the mempool is congested,
//! the floor rises automatically, creating natural back-pressure on spammers.
//! When congestion clears, the floor falls back to `MIN_FEE_BASE`.

use std::collections::VecDeque;

use noid_chain::consensus::params::MIN_FEE_BASE;

/// Tracks recently admitted fees and computes the dynamic floor.
pub struct FeeFloor {
    /// Ring buffer of the last `capacity` admitted fees.
    recent: VecDeque<u64>,
    /// Maximum entries before oldest is dropped.
    capacity: usize,
    /// Current computed floor (cached, updated on each push).
    current: u64,
}

impl FeeFloor {
    pub fn new(window_size: usize) -> Self {
        Self {
            recent: VecDeque::with_capacity(window_size),
            capacity: window_size.max(1),
            current: MIN_FEE_BASE,
        }
    }

    /// Record a newly admitted transaction's fee and recompute the floor.
    pub fn record(&mut self, fee: u64) {
        if self.recent.len() >= self.capacity {
            self.recent.pop_front();
        }
        self.recent.push_back(fee);
        self.current = self.compute();
    }

    /// Return the current dynamic fee floor (μNOID).
    #[inline]
    pub fn current(&self) -> u64 {
        self.current
    }

    /// Forget prior congestion after the mempool has drained completely.
    ///
    /// A historical admission must not leave an idle node enforcing a higher
    /// relay policy forever. Once no transaction remains, there is no live
    /// congestion signal and the next admission starts from the base floor.
    pub fn reset(&mut self) {
        self.recent.clear();
        self.current = MIN_FEE_BASE;
    }

    fn compute(&self) -> u64 {
        if self.recent.is_empty() {
            return MIN_FEE_BASE;
        }
        let median =
            noid_chain::consensus::median_u64(&self.recent.iter().copied().collect::<Vec<_>>());
        // Floor = 90% of median, never below MIN_FEE_BASE.
        let floor_90 = median.saturating_mul(9) / 10;
        floor_90.max(MIN_FEE_BASE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_starts_at_min_fee() {
        let f = FeeFloor::new(50);
        assert_eq!(f.current(), MIN_FEE_BASE);
    }

    #[test]
    fn floor_rises_with_high_fees() {
        let mut f = FeeFloor::new(10);
        for _ in 0..10 {
            f.record(100_000); // 0.1 NOID
        }
        assert!(f.current() > MIN_FEE_BASE, "floor must rise above minimum");
    }

    #[test]
    fn floor_never_below_min_fee() {
        let mut f = FeeFloor::new(10);
        for _ in 0..10 {
            f.record(0);
        }
        assert_eq!(f.current(), MIN_FEE_BASE);
    }

    #[test]
    fn floor_window_is_bounded() {
        let mut f = FeeFloor::new(3);
        f.record(1_000_000);
        f.record(1_000_000);
        f.record(1_000_000);
        let high = f.current();
        // Push many low fees to displace high ones.
        for _ in 0..10 {
            f.record(MIN_FEE_BASE);
        }
        assert!(f.current() < high, "old high fees should be replaced");
    }

    #[test]
    fn floor_resets_after_congestion_clears() {
        let mut f = FeeFloor::new(10);
        f.record(100_000);
        assert!(f.current() > MIN_FEE_BASE);

        f.reset();

        assert_eq!(f.current(), MIN_FEE_BASE);
        f.record(MIN_FEE_BASE);
        assert_eq!(f.current(), MIN_FEE_BASE);
    }
}
