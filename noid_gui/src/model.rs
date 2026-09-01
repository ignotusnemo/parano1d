// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

pub const WALLET_CONSOLIDATION_INPUT_LIMIT: usize = 64;
pub const MINED_BLOCK_PAGE_SIZE: u32 = 8;
pub const EXPLORER_PAGE_SIZE: u32 = 8;
pub const EXPLORER_SLOT_PAGE_SIZE: usize = 8;
pub const RECEIPT_PAGE_SIZE: u32 = 7;
pub const UTXO_PAGE_SIZE: usize = 25;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    English,
    Russian,
    Chinese,
}

impl Language {
    pub const ALL: [Self; 3] = [Self::English, Self::Russian, Self::Chinese];

    pub const fn code(self) -> &'static str {
        match self {
            Self::English => "EN",
            Self::Russian => "RU",
            Self::Chinese => "ZH",
        }
    }

    pub const fn native_name(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::Russian => "Русский",
            Self::Chinese => "简体中文",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeSyncStage {
    #[default]
    Headers,
    State,
    Tip,
}

#[derive(Clone, Default)]
pub struct SensitiveString(zeroize::Zeroizing<String>);

impl SensitiveString {
    pub fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.0);
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveString(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl LogLevel {
    pub const ALL: [Self; 4] = [Self::Error, Self::Warn, Self::Info, Self::Debug];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSettingsSnapshot {
    pub data_dir: String,
    pub p2p_listen: String,
    pub custom_seeds: Vec<String>,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixClass {
    B25,
    B255,
}

impl MatrixClass {
    pub const fn cli_value(self) -> &'static str {
        match self {
            Self::B25 => "b25",
            Self::B255 => "b255",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixCacheState {
    Pending,
    Preparing,
    Ready,
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofsTab {
    Mine,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    Interface,
    Secret,
    Node,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretImportMode {
    Raw,
    Photo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Present,
    Proofs,
    Mine,
    Explorer,
    Settings,
}

#[derive(Debug, Clone)]
pub struct AppSnapshot {
    pub network: NetworkSnapshot,
    pub addresses: Vec<AddressSnapshot>,
    pub active_address: usize,
    pub segments: Vec<SegmentSnapshot>,
    pub utxos: Vec<UtxoSnapshot>,
    pub mining: MiningSnapshot,
    pub mined_blocks: MinedBlocksSnapshot,
}

#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    pub height: u64,
    pub peers: usize,
    pub active_slots: u64,
    pub log_slots: u32,
    pub mempool_transactions: usize,
    pub mempool_capacity_transactions: usize,
    pub mempool_bytes: u64,
    pub mempool_capacity_bytes: u64,
    pub cpu_load: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub circulating_supply_micronoid: u128,
    pub block_reward_micronoid: u64,
    pub network_hashrate_hps: Option<f64>,
    pub average_block_time_ms: u64,
    pub difficulty: f64,
    pub pow_work_bits: Option<f64>,
    pub pow_work_change_percent: Option<f64>,
    pub difficulty_target: String,
    pub backend: String,
    pub synced: bool,
    pub sync_stage: NodeSyncStage,
    pub terminal_verified: bool,
    pub state_root: String,
}

impl NetworkSnapshot {
    pub fn slot_capacity(&self) -> u64 {
        1u64.checked_shl(self.log_slots).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct AddressSnapshot {
    pub key_index: u32,
    pub address: String,
    pub label: String,
    pub balance_micronoid: u64,
    pub utxo_count: usize,
    pub reserved_utxo_count: usize,
    pub pending_outbound_micronoid: u64,
    pub incoming_micronoid: u64,
}

impl AddressSnapshot {
    pub fn balance(&self) -> String {
        format_micronoid(self.balance_micronoid)
    }

    pub fn pending_outbound(&self) -> String {
        format_micronoid(self.pending_outbound_micronoid)
    }

    pub fn incoming(&self) -> String {
        format_micronoid(self.incoming_micronoid)
    }

    pub fn spendable_utxo_count(&self) -> usize {
        self.utxo_count.saturating_sub(self.reserved_utxo_count)
    }

    pub fn short_address(&self) -> String {
        if self.address.len() <= 26 {
            return self.address.clone();
        }

        format!(
            "{}…{}",
            &self.address[..15],
            &self.address[self.address.len() - 9..]
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SegmentSnapshot {
    pub occupancy: f32,
    pub live_count: u64,
    pub capacity: u64,
    pub owned: bool,
}

#[derive(Debug, Clone)]
pub struct UtxoSnapshot {
    pub slot_index: u32,
    pub value_micronoid: u64,
    pub creation_id: u64,
    pub segment: u8,
    pub reserved: bool,
}

impl UtxoSnapshot {
    pub fn value(&self) -> String {
        format_micronoid(self.value_micronoid)
    }
}

#[derive(Debug, Clone)]
pub struct MiningSnapshot {
    pub enabled: bool,
    pub ready: bool,
    pub isolated: bool,
    pub selected_threads: usize,
    pub available_threads: usize,
}

#[derive(Debug, Clone)]
pub struct MinedBlocksSnapshot {
    pub page: u32,
    pub total: usize,
    pub total_pages: u32,
    pub blocks: Vec<MinedBlockSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ReceiptsSnapshot {
    pub page: u32,
    pub total: usize,
    pub total_pages: u32,
    pub receipts: Vec<ReceiptSnapshot>,
}

impl ReceiptsSnapshot {
    pub fn empty() -> Self {
        Self {
            page: 1,
            total: 0,
            total_pages: 0,
            receipts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiptSnapshot {
    pub txid: String,
    pub height: u64,
    pub timestamp: u64,
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub peer_address: Option<String>,
    pub own_address: Option<String>,
    pub own_key_index: Option<u32>,
    pub input_count: usize,
    pub output_count: usize,
    pub receipt_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ReceiptDetailSnapshot {
    pub receipt_hex: String,
    pub verification: ReceiptVerificationSnapshot,
}

#[derive(Debug, Clone)]
pub struct ReceiptVerificationSnapshot {
    pub merkle_valid: bool,
    pub canonical: bool,
    pub confirmed: bool,
    pub error: Option<String>,
    pub authenticated_summary: Option<ReceiptSummarySnapshot>,
}

#[derive(Debug, Clone)]
pub struct ReceiptSummarySnapshot {
    pub txid: String,
    pub claimed_height: u64,
    pub confirmed_unix: u64,
    pub tx_index: u16,
    pub tx_count: u16,
    pub fee_micronoid: u64,
    pub inputs: Vec<ReceiptInputSnapshot>,
    pub outputs: Vec<ReceiptOutputSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ReceiptInputSnapshot {
    pub slot_index: u32,
    pub owner: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptOutputSnapshot {
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub owner: String,
}

impl MinedBlocksSnapshot {
    pub fn empty() -> Self {
        Self {
            page: 1,
            total: 0,
            total_pages: 0,
            blocks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MinedBlockSnapshot {
    pub height: u64,
    pub block_hash: String,
    pub timestamp: u64,
    pub reward_micronoid: u64,
    pub payout_key_index: u32,
    pub canonical: bool,
    pub confirmations: u64,
    pub full_block_available: bool,
}

impl MinedBlockSnapshot {
    pub fn reward(&self) -> String {
        format_micronoid(self.reward_micronoid)
    }

    pub fn short_hash(&self) -> String {
        if self.block_hash.is_empty() {
            return "UNKNOWN".into();
        }
        if self.block_hash.len() <= 20 {
            return self.block_hash.clone();
        }
        format!(
            "{}…{}",
            &self.block_hash[..11],
            &self.block_hash[self.block_hash.len() - 7..]
        )
    }
}

#[derive(Debug, Clone)]
pub struct BlockDetailsSnapshot {
    pub header: BlockHeaderSnapshot,
    pub retained: Option<RetainedBlockSnapshot>,
}

#[derive(Debug, Clone)]
pub struct BlockHeaderSnapshot {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub state_root: String,
    pub tx_root: String,
    pub timestamp: u64,
    pub miner: String,
    pub nonce_hex: String,
    pub difficulty_target: String,
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
}

#[derive(Debug, Clone)]
pub struct RetainedBlockSnapshot {
    pub proof_class: String,
    pub logical_transactions: u16,
    pub user_pages: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub reward_micronoid: u64,
    pub total_fees_micronoid: String,
    pub block_bytes: u64,
    pub history_step_bytes: u64,
    pub bundle_bytes: u64,
    pub transactions: Vec<BlockTransactionSnapshot>,
}

#[derive(Debug, Clone)]
pub struct BlockTransactionSnapshot {
    pub position: u16,
    pub txid: String,
    pub page_count: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub fee_micronoid: u64,
    pub coinbase: bool,
    pub development_payout: bool,
    pub epoch_anchor: String,
    pub input_owner: Option<String>,
    pub input_sum_micronoid: String,
    pub output_sum_micronoid: String,
    pub page_hashes: Vec<String>,
    pub inputs: Vec<BlockTransactionInputSnapshot>,
    pub outputs: Vec<BlockTransactionOutputSnapshot>,
}

#[derive(Debug, Clone)]
pub struct BlockTransactionInputSnapshot {
    pub page: u16,
    pub lane: u8,
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub creation_id: u64,
}

#[derive(Debug, Clone)]
pub struct BlockTransactionOutputSnapshot {
    pub page: u16,
    pub lane: u8,
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub owner: String,
    pub creation_id: u64,
}

#[derive(Debug, Clone)]
pub struct ExplorerSnapshot {
    pub tip_height: u64,
    pub block_page: u32,
    pub block_total_pages: u32,
    pub blocks: Vec<ExplorerBlockSnapshot>,
    pub recent_transactions: RecentTransactionsSnapshot,
}

impl ExplorerSnapshot {
    pub fn empty() -> Self {
        Self {
            tip_height: 0,
            block_page: 1,
            block_total_pages: 0,
            blocks: Vec::new(),
            recent_transactions: RecentTransactionsSnapshot::empty(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExplorerBlockSnapshot {
    pub header: BlockHeaderSnapshot,
    pub confirmations: u64,
    pub full_block_available: bool,
}

#[derive(Debug, Clone)]
pub struct RecentTransactionsSnapshot {
    pub page: u32,
    pub total: usize,
    pub total_pages: u32,
    pub tip_height: u64,
    pub retained_from_height: u64,
    pub transactions: Vec<RecentTransactionSnapshot>,
}

impl RecentTransactionsSnapshot {
    pub fn empty() -> Self {
        Self {
            page: 1,
            total: 0,
            total_pages: 0,
            tip_height: 0,
            retained_from_height: 0,
            transactions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecentTransactionSnapshot {
    pub height: u64,
    pub timestamp: u64,
    pub position: u16,
    pub txid: String,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub fee_micronoid: u64,
    pub coinbase: bool,
    pub development_payout: bool,
    pub address_spent_micronoid: Option<String>,
    pub address_received_micronoid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExplorerSlotSnapshot {
    pub slot_index: u32,
    pub value_micronoid: u64,
    pub creation_id: u64,
    pub owner: String,
    pub empty: bool,
}

#[derive(Debug, Clone)]
pub struct ExplorerAddressSnapshot {
    pub address: String,
    pub balance_micronoid: u128,
    pub slots: Vec<ExplorerSlotSnapshot>,
    pub recent_transactions: RecentTransactionsSnapshot,
}

#[derive(Debug, Clone)]
pub enum ExplorerSearchResultSnapshot {
    Address(ExplorerAddressSnapshot),
    Slot(ExplorerSlotSnapshot),
}

impl AppSnapshot {
    pub fn active_address(&self) -> &AddressSnapshot {
        &self.addresses[self.active_address]
    }

    pub fn activate_address(&mut self, key_index: u32) {
        if let Some(position) = self
            .addresses
            .iter()
            .position(|address| address.key_index == key_index)
        {
            self.active_address = position;
        }
    }

    pub fn rename_address(&mut self, key_index: u32, label: &str) {
        let label = label.trim();
        if label.is_empty() {
            return;
        }

        if let Some(address) = self
            .addresses
            .iter_mut()
            .find(|address| address.key_index == key_index)
        {
            address.label = label.to_string();
        }
    }

    pub fn create_preview_address(&mut self) {
        let key_index = self.addresses.len() as u32;
        self.addresses.push(AddressSnapshot {
            key_index,
            address: format!(
                "o1q{:02}n7k4v9s2p8m5x3d6ta0er4wh1yc5j7l9u3g6b2n8k5p4mc",
                key_index
            ),
            label: format!("Address {key_index}"),
            balance_micronoid: 0,
            utxo_count: 0,
            reserved_utxo_count: 0,
            pending_outbound_micronoid: 0,
            incoming_micronoid: 0,
        });
    }

    pub fn preserve_local_labels_from(&mut self, previous: &Self) {
        for address in &mut self.addresses {
            if let Some(previous_address) = previous
                .addresses
                .iter()
                .find(|candidate| candidate.key_index == address.key_index)
            {
                address.label.clone_from(&previous_address.label);
            }
        }
    }

    pub fn set_preview_mining_page(&mut self, page: u32) {
        self.mined_blocks = preview_mined_blocks(page);
    }

    pub fn offline(available_threads: usize) -> Self {
        Self {
            network: NetworkSnapshot {
                height: 0,
                peers: 0,
                active_slots: 0,
                log_slots: 24,
                mempool_transactions: 0,
                mempool_capacity_transactions: 1_024,
                mempool_bytes: 0,
                mempool_capacity_bytes: 384 * 1024 * 1024,
                cpu_load: 0.0,
                memory_used_bytes: 0,
                memory_total_bytes: 1,
                circulating_supply_micronoid: 0,
                block_reward_micronoid: 50_000_000,
                network_hashrate_hps: None,
                average_block_time_ms: 15_000,
                difficulty: 1.0,
                pow_work_bits: None,
                pow_work_change_percent: None,
                difficulty_target: String::new(),
                backend: "STARTING".into(),
                synced: false,
                sync_stage: NodeSyncStage::Headers,
                terminal_verified: false,
                state_root: "local-node-starting".into(),
            },
            addresses: vec![AddressSnapshot {
                key_index: 0,
                address: "Local wallet is starting…".into(),
                label: "Main".into(),
                balance_micronoid: 0,
                utxo_count: 0,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            }],
            active_address: 0,
            segments: vec![
                SegmentSnapshot {
                    occupancy: 0.0,
                    live_count: 0,
                    capacity: 1 << 16,
                    owned: false,
                };
                256
            ],
            utxos: Vec::new(),
            mining: MiningSnapshot {
                enabled: false,
                ready: false,
                isolated: false,
                selected_threads: available_threads,
                available_threads,
            },
            mined_blocks: MinedBlocksSnapshot::empty(),
        }
    }

    pub fn design_preview() -> Self {
        const PREVIEW_ADDRESS_COUNT: usize = 20;
        const PREVIEW_UTXO_COUNT: usize = 72;
        const PREVIEW_BALANCE_MICRONOID: u64 = 100_000_000_000;

        let segments = (0u32..256)
            .map(|index| {
                let mixed = index.wrapping_mul(0x9E37_79B9).rotate_left(index % 17) ^ 0xA5C3_18D7;
                let raw = ((mixed >> 9) & 0x7f) as f32 / 127.0;
                let occupancy = if raw < 0.16 {
                    0.0
                } else {
                    raw.powf(2.0) * 0.22
                };
                let occupancy = if matches!(index, 28 | 73 | 119 | 164 | 213) {
                    occupancy.max(0.04)
                } else {
                    occupancy
                };
                SegmentSnapshot {
                    occupancy,
                    live_count: (occupancy * (1u64 << 16) as f32).round() as u64,
                    capacity: 1 << 16,
                    owned: matches!(index, 28 | 73 | 119 | 164 | 213),
                }
            })
            .collect();

        let owned_segments = [28u8, 73, 119, 164, 213];
        let base_value = PREVIEW_BALANCE_MICRONOID / PREVIEW_UTXO_COUNT as u64;
        let remainder = PREVIEW_BALANCE_MICRONOID % PREVIEW_UTXO_COUNT as u64;
        let utxos = (0..PREVIEW_UTXO_COUNT)
            .rev()
            .map(|index| UtxoSnapshot {
                slot_index: 73 + index as u32 * 73,
                value_micronoid: base_value + u64::from((index as u64) < remainder),
                creation_id: 1_284_088 + index as u64 * 3,
                segment: owned_segments[index % owned_segments.len()],
                reserved: false,
            })
            .collect();

        let mut addresses = vec![
            AddressSnapshot {
                key_index: 0,
                address: "o12p4r8dl49ys3462zrqqys5vz8ll8m93su6lc70wu7rrwg3nn7fgsd7jnnt".into(),
                label: "Main".into(),
                balance_micronoid: PREVIEW_BALANCE_MICRONOID,
                utxo_count: PREVIEW_UTXO_COUNT,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 100_000_000_000,
                incoming_micronoid: 100_000_000_000,
            },
            AddressSnapshot {
                key_index: 1,
                address: "o17z7pfmh09rjztwga8y9pzpy05ncznl5teqe23a48d0sumjcnrlaszlk2vj".into(),
                label: "Savings".into(),
                balance_micronoid: 312_000_000,
                utxo_count: 6,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            },
            AddressSnapshot {
                key_index: 2,
                address: "o1ajnpfqtpkpugpwvpgjtkhk432fhd86l6vnvurgzn97hmvpcldpesewn8k6".into(),
                label: "Shop".into(),
                balance_micronoid: 0,
                utxo_count: 0,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            },
        ];
        addresses.extend((addresses.len()..PREVIEW_ADDRESS_COUNT).map(|key_index| {
            AddressSnapshot {
                key_index: key_index as u32,
                address: format!(
                    "o1q{key_index:02}n7k4v9s2p8m5x3d6ta0er4wh1yc5j7l9u3g6b2n8k5p4mc7x9m2qadc"
                ),
                label: format!("Address {key_index}"),
                balance_micronoid: 0,
                utxo_count: 0,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            }
        }));

        Self {
            network: NetworkSnapshot {
                height: 18_420,
                peers: 12,
                active_slots: 1_276_944,
                log_slots: 24,
                mempool_transactions: 7,
                mempool_capacity_transactions: 1_024,
                mempool_bytes: 2_936_832,
                mempool_capacity_bytes: 384 * 1024 * 1024,
                cpu_load: 0.147,
                memory_used_bytes: 12_300_000_000,
                memory_total_bytes: 31_000_000_000,
                circulating_supply_micronoid: 118_982_430_000,
                block_reward_micronoid: 50_000_000,
                network_hashrate_hps: Some(689_853.0),
                average_block_time_ms: 15_200,
                difficulty: 40.0,
                pow_work_bits: Some(23.321_928_094_887_36),
                pow_work_change_percent: Some(8.2),
                difficulty_target:
                    "9999999999999999999999999999999999999999999999999999999999010000".into(),
                backend: "AVX2".into(),
                synced: true,
                sync_stage: NodeSyncStage::Tip,
                terminal_verified: true,
                state_root: "a94f2c7718d95063e4770b423f5b7211ca60d2ea8cf7c8a4c9f35e7318c21c2e"
                    .into(),
            },
            addresses,
            active_address: 0,
            segments,
            utxos,
            mining: MiningSnapshot {
                enabled: false,
                ready: false,
                isolated: false,
                selected_threads: 12,
                available_threads: 12,
            },
            mined_blocks: preview_mined_blocks(1),
        }
    }
}

fn preview_mined_blocks(page: u32) -> MinedBlocksSnapshot {
    const TOTAL: usize = 23;
    let total_pages = (TOTAL as u32).div_ceil(MINED_BLOCK_PAGE_SIZE);
    let page = page.clamp(1, total_pages);
    let offset = (page - 1) * MINED_BLOCK_PAGE_SIZE;
    let count = MINED_BLOCK_PAGE_SIZE.min(TOTAL as u32 - offset);
    let blocks = (0..count)
        .map(|row| {
            let index = offset + row;
            let height = 18_420 - u64::from(index);
            let confirmations = u64::from(index) + 1;
            MinedBlockSnapshot {
                height,
                block_hash: format!("{:064x}", 0xa94f_2c77_18d9_5063u64.wrapping_add(height)),
                timestamp: 1_784_732_200u64.saturating_sub(u64::from(index) * 15),
                reward_micronoid: 50_000_000,
                payout_key_index: 0,
                canonical: true,
                confirmations,
                full_block_available: confirmations <= 18,
            }
        })
        .collect();
    MinedBlocksSnapshot {
        page,
        total: TOTAL,
        total_pages,
        blocks,
    }
}

pub fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let first = digits.len() % 3;
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);

    for (index, character) in digits.chars().enumerate() {
        if index > 0 && index % 3 == first {
            output.push('\u{2009}');
        }
        output.push(character);
    }

    output
}

/// Human-readable form of the consensus creation-id namespaces.
///
/// The high bit tags a coinbase output and the remaining bits encode its
/// block height. Ordinary outputs use the monotone output-id namespace.
pub fn format_creation_origin(creation_id: u64) -> String {
    const COINBASE_TAG: u64 = 1 << 63;

    if creation_id & COINBASE_TAG != 0 {
        format!("CB #{}", creation_id & !COINBASE_TAG)
    } else {
        format!("OUT #{creation_id}")
    }
}

pub fn format_micronoid(value: u64) -> String {
    let whole = value / 1_000_000;
    let fractional = value % 1_000_000;
    format!("{whole}.{fractional:06}")
}

pub fn format_micronoid_trimmed(value: u64) -> String {
    let mut formatted = format_micronoid(value);
    while formatted.ends_with('0') {
        formatted.pop();
    }
    if formatted.ends_with('.') {
        formatted.pop();
    }
    formatted
}

pub fn format_hashrate(hashrate_hps: Option<f64>) -> String {
    let Some(mut scaled) = hashrate_hps.filter(|value| value.is_finite() && *value > 0.0) else {
        return "—".into();
    };
    const UNITS: [&str; 7] = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];
    let mut unit = 0usize;
    while scaled >= 1_000.0 && unit + 1 < UNITS.len() {
        scaled /= 1_000.0;
        unit += 1;
    }
    let value = if scaled >= 100.0 {
        format!("{scaled:.0}")
    } else if scaled >= 10.0 {
        format!("{scaled:.1}")
    } else {
        format!("{scaled:.2}")
    };
    format!("~{value} {}", UNITS[unit])
}

pub fn format_pow_work_change(change_percent: Option<f64>) -> String {
    let Some(change) = change_percent.filter(|value| value.is_finite()) else {
        return "—".into();
    };
    if change > 0.05 {
        format!("↑ {:.1}%", change)
    } else if change < -0.05 {
        format!("↓ {:.1}%", -change)
    } else {
        "→ 0.0%".into()
    }
}

pub fn format_expected_pow_hashes(work_bits: Option<f64>) -> String {
    let Some(work_bits) = work_bits.filter(|value| value.is_finite() && *value >= 0.0) else {
        return "—".into();
    };
    let hashes = 2.0_f64.powf(work_bits);
    if !hashes.is_finite() {
        return "—".into();
    }
    const UNITS: [&str; 9] = ["", "K", "M", "B", "T", "Q", "Qi", "Sx", "Sp"];
    let mut scaled = hashes;
    let mut unit = 0usize;
    while scaled >= 1_000.0 && unit + 1 < UNITS.len() {
        scaled /= 1_000.0;
        unit += 1;
    }
    if scaled >= 1_000.0 {
        return format!("~{hashes:.2e} HASHES");
    }
    let value = if scaled >= 100.0 {
        format!("{scaled:.0}")
    } else if scaled >= 10.0 {
        format!("{scaled:.1}")
    } else {
        format!("{scaled:.2}")
    };
    format!("~{value}{} HASHES", UNITS[unit])
}

pub fn display_pow_target(target_hex_le: &str) -> Option<String> {
    let mut bytes = hex::decode(target_hex_le).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    bytes.reverse();
    Some(hex::encode(bytes))
}

pub fn format_compact_count(value: u64) -> String {
    const UNITS: [(&str, u128); 5] = [
        ("", 1),
        ("K", 1_000),
        ("M", 1_000_000),
        ("B", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ];

    let value = u128::from(value);
    let mut unit_index = UNITS
        .iter()
        .rposition(|(_, divisor)| value >= *divisor)
        .unwrap_or(0);

    loop {
        let (suffix, divisor) = UNITS[unit_index];
        let rounded_hundredths = value
            .checked_mul(100)
            .expect("u64 counts fit u128 compact formatting")
            .saturating_add(divisor / 2)
            / divisor;

        if rounded_hundredths >= 100_000 && unit_index + 1 < UNITS.len() {
            unit_index += 1;
            continue;
        }

        let whole = rounded_hundredths / 100;
        let fractional = (rounded_hundredths % 100) as u8;
        return match fractional {
            0 => format!("{whole}{suffix}"),
            value if value.is_multiple_of(10) => format!("{whole}.{}{suffix}", value / 10),
            value => format!("{whole}.{value:02}{suffix}"),
        };
    }
}

/// Formats the ASERT multiplier for the fixed-width status panels.
///
/// Values below one thousand retain the existing two-decimal display. Larger
/// values use short decimal units, then scientific notation beyond trillions.
pub fn format_compact_difficulty(value: f64) -> String {
    if !value.is_finite() || value < 0.0 {
        return "—".into();
    }

    const UNITS: [&str; 5] = ["", "K", "M", "B", "T"];
    let mut scaled = value;
    let mut unit = 0usize;
    while scaled >= 1_000.0 && unit + 1 < UNITS.len() {
        scaled /= 1_000.0;
        unit += 1;
    }

    let mut rounded = (scaled * 100.0).round() / 100.0;
    if rounded >= 1_000.0 && unit + 1 < UNITS.len() {
        rounded /= 1_000.0;
        unit += 1;
    }

    if unit == UNITS.len() - 1 && rounded >= 1_000.0 {
        let exponent = value.log10().floor() as i32;
        let mantissa = value / 10.0_f64.powi(exponent);
        return format!("{}e{exponent}", compact_decimal(mantissa));
    }

    if unit == 0 {
        format!("{rounded:.2}")
    } else {
        format!("{}{}", compact_decimal(rounded), UNITS[unit])
    }
}

fn compact_decimal(value: f64) -> String {
    let formatted = format!("{value:.2}");
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

/// Compact whole-network monetary value with at most two decimal places.
///
/// The caller supplies μNOID; the returned text deliberately omits the final
/// `NOID` suffix so views can retain it unconditionally at every window size.
pub fn format_compact_micronoid(value: u128) -> String {
    const UNITS: [(&str, u128); 5] = [
        ("", 1_000_000),
        ("K", 1_000_000_000),
        ("M", 1_000_000_000_000),
        ("B", 1_000_000_000_000_000),
        ("T", 1_000_000_000_000_000_000),
    ];

    let mut unit_index = UNITS
        .iter()
        .rposition(|(_, divisor)| value >= *divisor)
        .unwrap_or(0);

    loop {
        let (suffix, divisor) = UNITS[unit_index];
        let whole = value / divisor;
        let remainder = value % divisor;
        let rounded_hundredths = whole * 100 + (remainder * 100 + divisor / 2) / divisor;

        if rounded_hundredths >= 100_000 && unit_index + 1 < UNITS.len() {
            unit_index += 1;
            continue;
        }

        let scaled_whole = rounded_hundredths / 100;
        let fractional = (rounded_hundredths % 100) as u8;
        return match fractional {
            0 => format!("{scaled_whole}{suffix}"),
            value if value.is_multiple_of(10) => {
                format!("{scaled_whole}.{}{suffix}", value / 10)
            }
            value => format!("{scaled_whole}.{value:02}{suffix}"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{
        display_pow_target, format_compact_count, format_compact_difficulty,
        format_compact_micronoid, format_creation_origin, format_expected_pow_hashes,
        format_hashrate, format_micronoid_trimmed, format_pow_work_change, AppSnapshot,
        SensitiveString,
    };

    #[test]
    fn formats_creation_id_namespaces_semantically() {
        assert_eq!(format_creation_origin(4), "OUT #4");
        assert_eq!(format_creation_origin((1 << 63) | 1), "CB #1");
    }

    #[test]
    fn compacts_network_supply_without_losing_the_unit_scale() {
        assert_eq!(format_compact_micronoid(0), "0");
        assert_eq!(format_compact_micronoid(950_000_000), "950");
        assert_eq!(format_compact_micronoid(999_995_000), "1K");
        assert_eq!(format_compact_micronoid(118_982_430_000), "118.98K");
        assert_eq!(format_compact_micronoid(105_120_000_000_000), "105.12M");
        assert_eq!(format_compact_micronoid(1_230_000_000_000_000), "1.23B");
        assert_eq!(
            format_compact_micronoid(12_350_000_000_000_000_000),
            "12.35T"
        );
    }

    #[test]
    fn trims_only_insignificant_reward_decimals() {
        assert_eq!(format_micronoid_trimmed(50_000_000), "50");
        assert_eq!(format_micronoid_trimmed(12_500_000), "12.5");
        assert_eq!(format_micronoid_trimmed(3_125_000), "3.125");
        assert_eq!(format_micronoid_trimmed(1_562_500), "1.5625");
        assert_eq!(format_micronoid_trimmed(1_000_001), "1.000001");
    }

    #[test]
    fn formats_network_hashrate_as_an_explicit_estimate() {
        assert_eq!(format_hashrate(None), "—");
        assert_eq!(format_hashrate(Some(17_476.266)), "~17.5 KH/s");
        assert_eq!(format_hashrate(Some(1_118_481.0)), "~1.12 MH/s");
        assert_eq!(format_hashrate(Some(12_345_678_901.0)), "~12.3 GH/s");
    }

    #[test]
    fn formats_pow_work_detail_values() {
        let bits = Some(23.321_928_094_887_36);
        assert_eq!(format_expected_pow_hashes(bits), "~10.5M HASHES");
        assert_eq!(format_expected_pow_hashes(Some(18.0)), "~262K HASHES");
        assert_eq!(format_pow_work_change(Some(8.2)), "↑ 8.2%");
        assert_eq!(format_pow_work_change(Some(-5.14)), "↓ 5.1%");
        assert_eq!(format_pow_work_change(Some(0.01)), "→ 0.0%");
    }

    #[test]
    fn renders_numeric_pow_target_in_conventional_big_endian_order() {
        let little_endian = "9999999999999999999999999999999999999999999999999999999999010000";
        assert_eq!(
            display_pow_target(little_endian).as_deref(),
            Some("0000019999999999999999999999999999999999999999999999999999999999")
        );
        assert_eq!(display_pow_target("abcd"), None);
    }

    #[test]
    fn compacts_live_utxo_counts_without_hiding_small_networks() {
        assert_eq!(format_compact_count(0), "0");
        assert_eq!(format_compact_count(999), "999");
        assert_eq!(format_compact_count(1_000), "1K");
        assert_eq!(format_compact_count(2_567), "2.57K");
        assert_eq!(format_compact_count(999_995), "1M");
        assert_eq!(format_compact_count(1_276_944), "1.28M");
        assert_eq!(format_compact_count(4_294_967_296), "4.29B");
    }

    #[test]
    fn compacts_difficulty_without_changing_small_values() {
        assert_eq!(format_compact_difficulty(93.718), "93.72");
        assert_eq!(format_compact_difficulty(999.99), "999.99");
        assert_eq!(format_compact_difficulty(1_000.0), "1K");
        assert_eq!(format_compact_difficulty(12_345.0), "12.35K");
        assert_eq!(format_compact_difficulty(999_995.0), "1M");
        assert_eq!(format_compact_difficulty(1_250_000.0), "1.25M");
        assert_eq!(format_compact_difficulty(1_000_000_000.0), "1B");
        assert_eq!(format_compact_difficulty(1.0e15), "1e15");
        assert_eq!(format_compact_difficulty(f64::INFINITY), "—");
    }

    #[test]
    fn sensitive_strings_are_redacted_and_explicitly_cleared() {
        let secret = "11".repeat(32);
        let mut value = SensitiveString::new(secret.clone());

        let debug = format!("{value:?}");
        assert!(!debug.contains(&secret));
        assert_eq!(debug, "SensitiveString(<redacted>)");

        value.clear();
        assert!(value.is_empty());
    }

    #[test]
    fn preview_address_creation_does_not_change_the_active_owner() {
        let mut snapshot = AppSnapshot::design_preview();
        let active_index = snapshot.active_address;
        let active_key_index = snapshot.active_address().key_index;
        let utxo_slots = snapshot
            .utxos
            .iter()
            .map(|utxo| utxo.slot_index)
            .collect::<Vec<_>>();
        let address_count = snapshot.addresses.len();

        snapshot.create_preview_address();

        assert_eq!(snapshot.addresses.len(), address_count + 1);
        assert_eq!(snapshot.active_address, active_index);
        assert_eq!(snapshot.active_address().key_index, active_key_index);
        assert_eq!(
            snapshot
                .utxos
                .iter()
                .map(|utxo| utxo.slot_index)
                .collect::<Vec<_>>(),
            utxo_slots
        );
    }

    #[test]
    fn preview_addresses_match_the_canonical_display_width() {
        let snapshot = AppSnapshot::design_preview();
        assert!(snapshot
            .addresses
            .iter()
            .all(|address| address.address.chars().count() == 60));
    }
}
