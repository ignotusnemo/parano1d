use super::*;
use crate::acceptance::trace::native_assets::financial_kernel::{
    FinancialKernelConfig, FinancialKernelPhase,
};
use crate::acceptance::trace::native_assets::sequential_trade::kernel::TradeKernelConfig;
use noid_chain::consensus::forks::ForkSchedule;
use noid_ivc_core::public_io::WitnessSlice;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeFinancialConfig {
    pub action_capacity: usize,
    pub kernel: FinancialKernelConfig,
    pub phase: FinancialKernelPhase,
}

/// Explicit, unfrozen research parameters. Neither environment variables nor
/// the active mainnet schedule can silently select a candidate proof bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2Config {
    outer_m: usize,
    pages: usize,
    max_live_inputs: usize,
    contract_slots: usize,
    schedule: ForkSchedule,
    authorization_activation: Option<u64>,
    native_header_capacity: Option<usize>,
    native_financial: Option<NativeFinancialConfig>,
    native_sequential: Option<TradeKernelConfig>,
}

impl V2Config {
    pub fn new(outer_m: usize, pages: usize, schedule: ForkSchedule) -> Result<Self, V2Error> {
        Self::with_input_budget(
            outer_m,
            pages,
            pages
                .saturating_mul(noid_tx::TX_INPUTS)
                .min(noid_chain::consensus::params::BLOCK_MAX_LIVE_INPUTS),
            schedule,
        )
    }

    /// Explicit research profile. The bounded-input shape is deliberately a
    /// separate bank identity; it cannot change a previously frozen recipe.
    pub fn with_input_budget(
        outer_m: usize,
        pages: usize,
        max_live_inputs: usize,
        schedule: ForkSchedule,
    ) -> Result<Self, V2Error> {
        Self::with_limits(
            outer_m,
            pages,
            max_live_inputs,
            super::super::V2_CONTRACT_SLOTS,
            schedule,
        )
    }

    /// All capacity limits belong to the proof-bank identity, never to the
    /// witness. This permits measuring larger call envelopes before freezing.
    pub fn with_limits(
        outer_m: usize,
        pages: usize,
        max_live_inputs: usize,
        contract_slots: usize,
        schedule: ForkSchedule,
    ) -> Result<Self, V2Error> {
        let activation = schedule.v2().ok_or(V2Error::Boundary)?;
        if !(23..=25).contains(&outer_m)
            || crate::region_sidecar::selected_zk_block_geometry_with_inputs(pages, max_live_inputs)
                .is_none()
            || activation.height() <= 1
            || 86_400 % activation.block_time() != 0
            || contract_slots == 0
            || contract_slots > pages
        {
            return Err(V2Error::Runtime);
        }
        Ok(Self {
            outer_m,
            pages,
            max_live_inputs,
            contract_slots,
            schedule,
            authorization_activation: None,
            native_header_capacity: None,
            native_financial: None,
            native_sequential: None,
        })
    }

    pub fn with_authorization_update(mut self, height: u64) -> Result<Self, V2Error> {
        if height <= self.schedule.v2().ok_or(V2Error::Boundary)?.height() {
            return Err(V2Error::Boundary);
        }
        self.authorization_activation = Some(height);
        Ok(self)
    }

    pub const fn authorization_activation(self) -> Option<u64> {
        self.authorization_activation
    }

    /// Native object operations share the updated authorization boundary.
    /// Zero headers selects ordinary transactions with the same allocation namespace.
    pub fn with_native_assets(mut self, headers: usize) -> Result<Self, V2Error> {
        if self.authorization_activation.is_none() || headers > self.pages || headers > 64 {
            return Err(V2Error::Runtime);
        }
        self.native_header_capacity = Some(headers);
        self.native_financial = None;
        self.native_sequential = None;
        Ok(self)
    }

    /// Native finance uses a separate fixed recipe with complete-set work bounds.
    pub fn with_native_finance(
        mut self,
        headers: usize,
        actions: usize,
        settlement_actions: usize,
    ) -> Result<Self, V2Error> {
        if self.authorization_activation.is_none()
            || headers == 0
            || headers > self.pages
            || headers > 64
            || actions < 34
            || actions > 256
            || actions > (10 * self.pages).next_power_of_two()
            || 2 * headers > actions.next_power_of_two()
            || settlement_actions < 34
            || settlement_actions > actions
            || settlement_actions % 2 != 0
        {
            return Err(V2Error::Runtime);
        }
        self.native_header_capacity = Some(headers);
        self.native_financial = Some(NativeFinancialConfig {
            action_capacity: actions,
            phase: FinancialKernelPhase::Complete,
            kernel: FinancialKernelConfig {
                definition_capacity: headers,
                control_capacity: 2 * headers,
                registered_control_capacity: headers,
                settlement_action_capacity: settlement_actions,
            },
        });
        self.native_sequential = None;
        Ok(self)
    }

    /// One global policy, source and execution budget covers every market.
    pub fn with_native_sequential_finance(
        self,
        headers: usize,
        actions: usize,
        trade: TradeKernelConfig,
    ) -> Result<Self, V2Error> {
        if self.outer_m > 24
            || !(1..=noid_tx::native_assets::market::sequential::MAX_SEQUENTIAL_TRADES)
                .contains(&trade.policies)
            || !(1..=trade.policies).contains(&trade.markets)
            || trade.markets > headers
            || trade.funding < trade.policies
            || trade.funding > actions
            || trade.funding > self.max_live_inputs
            || trade.policies > self.pages
        {
            return Err(V2Error::Runtime);
        }
        let mut config = self.with_native_finance(headers, actions, 34)?;
        let financial = config.native_financial.as_mut().ok_or(V2Error::Runtime)?;
        financial.kernel.definition_capacity =
            headers.checked_add(trade.markets).ok_or(V2Error::Runtime)?;
        financial.kernel.control_capacity = headers;
        config.native_sequential = Some(trade);
        Ok(config)
    }

    pub const fn native_sequential_config(self) -> Option<TradeKernelConfig> {
        self.native_sequential
    }

    pub const fn native_financial_config(self) -> Option<NativeFinancialConfig> {
        self.native_financial
    }

    pub fn with_native_financial_phase(
        mut self,
        phase: FinancialKernelPhase,
    ) -> Result<Self, V2Error> {
        if self.native_sequential.is_some() && phase != FinancialKernelPhase::Complete {
            return Err(V2Error::Runtime);
        }
        let financial = self.native_financial.as_mut().ok_or(V2Error::Runtime)?;
        financial.phase = phase;
        Ok(self)
    }

    pub const fn native_header_capacity(self) -> Option<usize> {
        self.native_header_capacity
    }

    pub fn native_action_capacity(self) -> Option<usize> {
        self.native_financial
            .map(|config| config.action_capacity)
            .or_else(|| self.native_header_capacity.map(|headers| 4 * headers))
    }

    pub const fn authorization_version(self) -> noid_tx::OwnerAuthorizationVersion {
        match self.authorization_activation {
            Some(_) => noid_tx::OwnerAuthorizationVersion::V4,
            None => noid_tx::OwnerAuthorizationVersion::V3,
        }
    }

    pub fn outer_m(self) -> usize {
        self.outer_m
    }
    pub fn pages(self) -> usize {
        self.pages
    }
    pub fn max_live_inputs(self) -> usize {
        self.max_live_inputs
    }
    pub fn contract_slots(self) -> usize {
        self.contract_slots
    }
    pub(crate) fn block_geometry(self) -> crate::region_sidecar::SelectedZkBlockGeometry {
        let mut geometry = crate::region_sidecar::selected_zk_block_geometry_with_inputs(
            self.pages,
            self.max_live_inputs,
        )
        .expect("checked candidate geometry");
        geometry.authorization_version = self.authorization_version();
        geometry
    }
    pub fn schedule(self) -> ForkSchedule {
        self.schedule
    }
    pub fn activation_height(self) -> u64 {
        self.authorization_activation
            .unwrap_or(self.schedule.v2().unwrap().height())
    }
    pub fn block_time(self) -> u64 {
        self.schedule.v2().unwrap().block_time()
    }
    pub fn shape(self) -> FieldShape {
        FieldShape {
            m: self.outer_m,
            k_log: self.outer_m,
            k_skip: noid_ivc_core::zerocheck::K_SKIP,
            const_pin: Some(0),
        }
    }
    pub fn pcs_params(self) -> PcsParams {
        PcsParams {
            m: self.outer_m + noid_ivc_core::pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        }
    }
    pub(super) fn layout(self) -> IoLayout {
        let point_len = 2 * self.outer_m + 1;
        let value = bank::POINT + 2 * point_len;
        let live = value + 2;
        let acc = live + 1;
        IoLayout {
            point_len,
            value,
            live,
            acc,
            len: acc + 10,
        }
    }
    pub fn io_spec(self) -> PublicIoSpec {
        let len = self.layout().len;
        PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: len.next_power_of_two().trailing_zeros() as usize,
                index: 1,
            },
            io_len: len,
            claims: Vec::new(),
        }
    }
    pub(super) fn identity_bytes(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = [
            self.outer_m as u64,
            self.pages as u64,
            self.schedule.v1_1_height().unwrap(),
            self.schedule.v2().unwrap().height(),
            self.block_time(),
            self.max_live_inputs as u64,
            self.contract_slots as u64,
            noid_tx::experimental_object::OBJECT_VERSION as u64,
        ]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
        if let Some(height) = self.authorization_activation {
            bytes.extend_from_slice(&(self.authorization_version() as u8 as u64).to_le_bytes());
            bytes.extend_from_slice(&height.to_le_bytes());
        }
        if let Some(capacity) = self.native_header_capacity {
            bytes.extend_from_slice(b"NATOBJ21");
            bytes.extend_from_slice(&(capacity as u64).to_le_bytes());
            bytes.extend_from_slice(&noid_chain::state::native_assets::native_chain_id());
        }
        if let Some(config) = self.native_financial {
            bytes.extend_from_slice(b"NATFIN21");
            for value in [
                config.action_capacity,
                config.kernel.definition_capacity,
                config.kernel.control_capacity,
                config.kernel.registered_control_capacity,
                config.kernel.settlement_action_capacity,
            ] {
                bytes.extend_from_slice(&(value as u64).to_le_bytes());
            }
            if config.phase != FinancialKernelPhase::Complete {
                bytes.extend_from_slice(b"FINPH21!");
                bytes.extend_from_slice(&(config.phase as u8 as u64).to_le_bytes());
            }
        }
        if let Some(config) = self.native_sequential {
            bytes.extend_from_slice(b"NATTRD21");
            for value in [config.markets, config.policies, config.funding] {
                bytes.extend_from_slice(&(value as u64).to_le_bytes());
            }
        }
        bytes
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct IoLayout {
    pub point_len: usize,
    pub value: usize,
    pub live: usize,
    pub acc: usize,
    pub len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::forks::V2Activation;

    #[test]
    fn input_budget_has_an_explicit_shape_and_bank_identity() {
        let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
        let full = V2Config::new(23, 96, schedule).unwrap();
        let bounded = V2Config::with_input_budget(23, 96, 384, schedule).unwrap();
        assert_eq!(full.max_live_inputs(), 768);
        assert_eq!(full.identity_bytes().len(), 64);
        assert_eq!(bounded.identity_bytes().len(), 64);
        assert_ne!(full.identity_bytes(), bounded.identity_bytes());
        assert_eq!(bounded.block_geometry().touched_capacity, 577);
        assert_eq!(bounded.block_geometry().segment_capacity, 256);
        assert_eq!(bounded.block_geometry().meta_b_block_log, 9);
        assert_eq!(full.block_geometry().meta_b_block_log, 10);
        assert_eq!(
            bounded.block_geometry().auth_tiles,
            full.block_geometry().auth_tiles
        );
        assert_eq!(noid_tx::TX_INPUTS, 8);
        for (pages, inputs) in [(96, 0), (96, 385), (96, 769), (63, 384), (63, 505)] {
            assert!(V2Config::with_input_budget(23, pages, inputs, schedule).is_err());
        }
        assert!(V2Config::new(23, usize::MAX, schedule).is_err());
    }

    #[test]
    fn capacity_sweep_keeps_input_limits_and_distinct_bank_identities() {
        let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
        let mut identities = std::collections::HashSet::new();
        for pages in [
            96, 112, 120, 127, 128, 192, 206, 207, 209, 210, 211, 223, 255,
        ] {
            for inputs in [256, 384, 504] {
                let config = V2Config::with_input_budget(23, pages, inputs, schedule).unwrap();
                let geometry = config.block_geometry();
                assert_eq!(geometry.tier, pages);
                assert_eq!(geometry.touched_capacity, inputs + 2 * pages + 1);
                assert_eq!(geometry.auth_tiles, (pages + 1).next_power_of_two());
                assert_eq!(config.max_live_inputs(), inputs);
                assert!(identities.insert(config.identity_bytes()));
            }
        }
        assert!(V2Config::with_input_budget(23, 129, 384, schedule).is_err());
        assert!(V2Config::with_input_budget(23, 127, 257, schedule).is_err());
    }

    #[test]
    fn call_capacity_is_explicit_and_bound_into_the_bank() {
        let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
        let mut identities = std::collections::HashSet::new();
        for calls in [1, 16, 32, 96] {
            let config = V2Config::with_limits(23, 96, 384, calls, schedule).unwrap();
            assert_eq!(config.contract_slots(), calls);
            assert!(identities.insert(config.identity_bytes()));
        }
        for calls in [0, 97, usize::MAX] {
            assert!(V2Config::with_limits(23, 96, 384, calls, schedule).is_err());
        }
    }
}
