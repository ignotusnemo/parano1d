// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-size production telemetry for the snapshot-sync scaling phases.
//!
//! This deliberately retains only scalar totals for the currently active
//! sync.  It never stores per-header, per-segment, or per-block samples.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncPhase {
    HeaderDiskValidation,
    HistoryStepTerminal,
    SnapshotState,
    RetainedSuffix,
}

impl SyncPhase {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::HeaderDiskValidation => "header_disk_validation",
            Self::HistoryStepTerminal => "history_step_terminal",
            Self::SnapshotState => "snapshot_segment_stage_install",
            Self::RetainedSuffix => "retained_suffix_apply",
        }
    }

    pub(crate) const fn scaling(self) -> &'static str {
        match self {
            Self::HeaderDiskValidation => "O(H)",
            Self::HistoryStepTerminal => "O(1)",
            Self::SnapshotState => "O(state)",
            Self::RetainedSuffix => "O(tail)",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SyncPhaseMeasurement {
    pub(crate) phase: SyncPhase,
    pub(crate) count: u64,
    pub(crate) bytes: u64,
    pub(crate) elapsed: Duration,
    pub(crate) succeeded: bool,
}

impl SyncPhaseMeasurement {
    pub(crate) const fn new(
        phase: SyncPhase,
        count: u64,
        bytes: u64,
        elapsed: Duration,
        succeeded: bool,
    ) -> Self {
        Self {
            phase,
            count,
            bytes,
            elapsed,
            succeeded,
        }
    }

    pub(crate) fn elapsed_ms(self) -> u64 {
        self.elapsed.as_millis().min(u128::from(u64::MAX)) as u64
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PhaseAccumulator {
    count: u64,
    bytes: u64,
    elapsed: Duration,
}

impl PhaseAccumulator {
    fn add_work(&mut self, elapsed: Duration) {
        self.elapsed = self.elapsed.saturating_add(elapsed);
    }

    fn observe_scale(&mut self, count: u64, bytes: u64) {
        self.count = self.count.max(count);
        self.bytes = self.bytes.max(bytes);
    }

    fn add_item(&mut self, bytes: u64, elapsed: Duration) {
        self.count = self.count.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        self.add_work(elapsed);
    }

    fn finish(&mut self, phase: SyncPhase) -> SyncPhaseMeasurement {
        let completed = std::mem::take(self);
        SyncPhaseMeasurement::new(
            phase,
            completed.count,
            completed.bytes,
            completed.elapsed,
            true,
        )
    }
}

/// Constant-memory totals for exactly one selected snapshot and its retained
/// suffix.  All methods are O(1); no method allocates or retains samples.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SnapshotSyncTelemetry {
    headers: PhaseAccumulator,
    state: PhaseAccumulator,
    suffix: PhaseAccumulator,
    suffix_target_height: u64,
    suffix_active: bool,
    transfer: StateTransferAccumulator,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StateTransferAccumulator {
    started: Option<Instant>,
    network_requests: u64,
    network_segments: u64,
    canonical_download_bytes: u64,
    wire_payload_bytes: u64,
    v5_segments: u64,
    v6_segments: u64,
    compressed_segments: u64,
    reused_segments: u64,
    reused_bytes: u64,
}

impl SnapshotSyncTelemetry {
    /// Start a fresh selected snapshot.  Any incomplete prior measurements are
    /// abandoned rather than merged across incomparable sync generations.
    pub(crate) fn begin_snapshot(&mut self) {
        self.reset();
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn record_header_work(&mut self, elapsed: Duration) {
        self.headers.add_work(elapsed);
    }

    pub(crate) fn observe_header_scale(&mut self, count: u64, bytes: u64) {
        self.headers.observe_scale(count, bytes);
    }

    pub(crate) fn finish_headers(&mut self) -> SyncPhaseMeasurement {
        self.headers.finish(SyncPhase::HeaderDiskValidation)
    }

    pub(crate) fn record_state_segment(&mut self, bytes: u64, elapsed: Duration) {
        self.state.add_item(bytes, elapsed);
    }

    pub(crate) fn begin_state_transfer(&mut self) {
        self.transfer = StateTransferAccumulator {
            started: Some(Instant::now()),
            ..Default::default()
        };
    }

    pub(crate) fn record_state_download(
        &mut self,
        transport: noid_p2p::protocol::StateSegmentTransport,
        canonical_bytes: u64,
        segments: u64,
    ) {
        self.transfer.network_requests = self.transfer.network_requests.saturating_add(1);
        self.transfer.network_segments = self.transfer.network_segments.saturating_add(segments);
        self.transfer.canonical_download_bytes = self
            .transfer
            .canonical_download_bytes
            .saturating_add(canonical_bytes);
        self.transfer.wire_payload_bytes = self
            .transfer
            .wire_payload_bytes
            .saturating_add(transport.payload_bytes);
        if transport.version == 5 {
            self.transfer.v5_segments = self.transfer.v5_segments.saturating_add(segments);
        } else if transport.version == 6 {
            self.transfer.v6_segments = self.transfer.v6_segments.saturating_add(segments);
            if transport.payload_bytes < canonical_bytes {
                self.transfer.compressed_segments =
                    self.transfer.compressed_segments.saturating_add(segments);
            }
        }
    }

    pub(crate) fn record_state_reuse(&mut self, count: u64, bytes: u64, elapsed: Duration) {
        self.transfer.reused_segments = self.transfer.reused_segments.saturating_add(count);
        self.transfer.reused_bytes = self.transfer.reused_bytes.saturating_add(bytes);
        self.state.count = self.state.count.saturating_add(count);
        self.state.bytes = self.state.bytes.saturating_add(bytes);
        self.state.add_work(elapsed);
    }

    pub(crate) fn log_state_transfer(&mut self) {
        let transfer = std::mem::take(&mut self.transfer);
        if let Some(started) = transfer.started {
            tracing::info!(
                phase = "snapshot_state_transfer",
                elapsed_ms = started.elapsed().as_millis() as u64,
                timing_basis = "wall",
                network_requests = transfer.network_requests,
                network_segments = transfer.network_segments,
                canonical_download_bytes = transfer.canonical_download_bytes,
                wire_payload_bytes = transfer.wire_payload_bytes,
                v5_segments = transfer.v5_segments,
                v6_segments = transfer.v6_segments,
                compressed_segments = transfer.compressed_segments,
                reused_segments = transfer.reused_segments,
                reused_bytes = transfer.reused_bytes,
                "snapshot State transfer and local reuse completed"
            );
        }
    }

    pub(crate) fn record_state_work(&mut self, elapsed: Duration) {
        self.state.add_work(elapsed);
    }

    pub(crate) fn finish_state(&mut self) -> SyncPhaseMeasurement {
        self.state.finish(SyncPhase::SnapshotState)
    }

    /// Emit the immutable bridge plus disk live-tail replay completed as part
    /// of snapshot installation. The replay is already complete, so it does
    /// not need the incremental post-install suffix state machine below.
    pub(crate) fn complete_staged_tail(
        &mut self,
        count: u64,
        bytes: u64,
        elapsed: Duration,
    ) -> SyncPhaseMeasurement {
        self.suffix = PhaseAccumulator::default();
        self.suffix_active = false;
        self.suffix_target_height = 0;
        SyncPhaseMeasurement::new(SyncPhase::RetainedSuffix, count, bytes, elapsed, true)
    }

    /// Begin the post-snapshot retained suffix.  An empty suffix is completed
    /// immediately and therefore still emits an honest zero-count sample.
    pub(crate) fn begin_suffix(
        &mut self,
        installed_height: u64,
        target_height: u64,
    ) -> Option<SyncPhaseMeasurement> {
        self.suffix = PhaseAccumulator::default();
        self.suffix_target_height = target_height.max(installed_height);
        self.suffix_active = self.suffix_target_height > installed_height;
        (!self.suffix_active).then(|| self.suffix.finish(SyncPhase::RetainedSuffix))
    }

    pub(crate) fn extend_suffix_target(&mut self, target_height: u64) {
        if self.suffix_active {
            self.suffix_target_height = self.suffix_target_height.max(target_height);
        }
    }

    #[cfg(test)]
    pub(crate) fn record_suffix_block(
        &mut self,
        height: u64,
        bytes: u64,
        elapsed: Duration,
    ) -> Option<SyncPhaseMeasurement> {
        if !self.suffix_active {
            return None;
        }
        self.suffix.add_item(bytes, elapsed);
        if height < self.suffix_target_height {
            return None;
        }
        self.suffix_active = false;
        Some(self.suffix.finish(SyncPhase::RetainedSuffix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_totals_are_separate_and_reset_together() {
        let mut telemetry = SnapshotSyncTelemetry::default();
        telemetry.begin_snapshot();
        telemetry.record_header_work(Duration::from_millis(7));
        telemetry.observe_header_scale(12, 2_544);
        telemetry.record_state_segment(4_096, Duration::from_millis(11));
        telemetry.record_state_work(Duration::from_millis(3));

        let headers = telemetry.finish_headers();
        let state = telemetry.finish_state();
        assert_eq!(headers.phase, SyncPhase::HeaderDiskValidation);
        assert_eq!((headers.count, headers.bytes), (12, 2_544));
        assert_eq!(headers.elapsed, Duration::from_millis(7));
        assert_eq!(state.phase, SyncPhase::SnapshotState);
        assert_eq!((state.count, state.bytes), (1, 4_096));
        assert_eq!(state.elapsed, Duration::from_millis(14));

        telemetry.record_header_work(Duration::from_secs(1));
        telemetry.record_state_segment(1, Duration::from_secs(1));
        telemetry.reset();
        assert_eq!(telemetry, SnapshotSyncTelemetry::default());
    }

    #[test]
    fn terminal_measurement_is_an_independent_constant_phase() {
        let terminal = SyncPhaseMeasurement::new(
            SyncPhase::HistoryStepTerminal,
            1,
            61 * 1_024,
            Duration::from_millis(42),
            true,
        );
        assert_eq!(terminal.phase.scaling(), "O(1)");
        assert_eq!(terminal.elapsed_ms(), 42);
        assert_eq!(terminal.count, 1);
    }

    #[test]
    fn staged_tail_is_reported_without_incremental_recounting() {
        let mut telemetry = SnapshotSyncTelemetry::default();
        let completed = telemetry.complete_staged_tail(18, 42_000, Duration::from_millis(90));
        assert_eq!(completed.phase, SyncPhase::RetainedSuffix);
        assert_eq!((completed.count, completed.bytes), (18, 42_000));
        assert_eq!(completed.elapsed, Duration::from_millis(90));
        assert!(telemetry
            .record_suffix_block(19, 1, Duration::from_millis(1))
            .is_none());
    }

    #[test]
    fn suffix_counts_only_until_the_fixed_target() {
        let mut telemetry = SnapshotSyncTelemetry::default();
        assert!(telemetry.begin_suffix(100, 102).is_none());
        assert!(telemetry
            .record_suffix_block(101, 10, Duration::from_millis(2))
            .is_none());
        let completed = telemetry
            .record_suffix_block(102, 20, Duration::from_millis(3))
            .expect("target block completes the suffix");
        assert_eq!(completed.phase, SyncPhase::RetainedSuffix);
        assert_eq!((completed.count, completed.bytes), (2, 30));
        assert_eq!(completed.elapsed, Duration::from_millis(5));
        assert!(telemetry
            .record_suffix_block(103, 99, Duration::from_secs(1))
            .is_none());
    }

    #[test]
    fn telemetry_state_is_fixed_size_and_owns_no_heap_storage() {
        assert!(std::mem::size_of::<SnapshotSyncTelemetry>() <= 256);
        assert!(!std::mem::needs_drop::<SnapshotSyncTelemetry>());
        assert!(!std::mem::needs_drop::<SyncPhaseMeasurement>());
    }
}
