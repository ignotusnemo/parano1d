// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::time::{Duration, Instant};

use iced::widget::text_editor;
use iced::{Element, Subscription, Task};

use crate::backend::{
    Backend, BackendSnapshot, ConsolidationPlan, ConsolidationSubmission, ExplorerLookup, NodeMode,
    PaymentSubmission,
};
use crate::model::{
    AppSnapshot, BlockDetailsSnapshot, ExplorerSearchResultSnapshot, ExplorerSnapshot, Language,
    LogLevel, MatrixCacheState, MatrixClass, NodeSettingsSnapshot, ProofsTab,
    ReceiptDetailSnapshot, ReceiptVerificationSnapshot, ReceiptsSnapshot, SecretImportMode,
    Section, SensitiveString, SettingsTab, EXPLORER_SLOT_PAGE_SIZE, UTXO_PAGE_SIZE,
    WALLET_CONSOLIDATION_INPUT_LIMIT,
};
use crate::secret::PreparedPhoto;
use crate::view;

pub const BLOCK_DETAILS_SCROLL_ID: &str = "block-details-scroll";
pub const TRANSACTION_DETAILS_SCROLL_ID: &str = "transaction-details-scroll";
pub const NODE_LOG_LINE_LIMIT: usize = 80;

const PHOTO_SCAN_FRAME: Duration = Duration::from_millis(33);
const PROOF_FORGE_FRAME: Duration = Duration::from_millis(33);
const SHUTDOWN_FORGE_FRAME: Duration = Duration::from_millis(33);
const LANGUAGE_FORGE_FRAME: Duration = Duration::from_millis(33);
const CONSOLIDATION_HINT_CLOSE_FRAME: Duration = Duration::from_millis(80);
const HEADER_COIN_FRAME: Duration = Duration::from_millis(66);
const HEADER_COIN_TURN_SECONDS: f32 = 8.5;
const NODE_LOG_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const NODE_LOG_BYTE_LIMIT: u64 = 64 * 1024;
const PHOTO_SCAN_COMPLETE_HOLD: Duration = Duration::from_millis(160);
const PHOTO_SCAN_SPEED: f32 = 0.58;
const PHOTO_SCAN_CRAWL_SPEED: f32 = 0.025;
const PHOTO_SCAN_WAIT_THRESHOLD: f32 = 0.88;
const PHOTO_SCAN_WAIT_LIMIT: f32 = 0.975;
const PHOTO_SCAN_RESPONSE: f32 = 9.0;

fn node_log_content(contents: &str) -> text_editor::Content {
    let mut content = text_editor::Content::with_text(contents);
    content.perform(text_editor::Action::Move(text_editor::Motion::DocumentEnd));
    content
}

#[derive(Debug)]
pub struct App {
    pub snapshot: AppSnapshot,
    pub section: Section,
    pub backend_state: BackendState,
    pub backend_error: Option<String>,
    pub node_action_in_flight: bool,
    pub mining_page: u32,
    pub proofs_tab: ProofsTab,
    pub receipts: ReceiptsSnapshot,
    pub receipt_page: u32,
    pub receipts_loading: bool,
    receipts_loaded_height: Option<u64>,
    pub selected_receipt_txid: Option<String>,
    pub receipt_detail: Option<ReceiptDetailSnapshot>,
    pub receipt_detail_loading: bool,
    pub receipt_editor: text_editor::Content,
    pub receipt_verification: Option<ReceiptVerificationSnapshot>,
    pub receipt_verifying: bool,
    pub receipt_error: Option<String>,
    pub explorer: ExplorerSnapshot,
    pub explorer_block_page: u32,
    pub explorer_transaction_page: u32,
    pub explorer_slot_page: usize,
    pub explorer_query: String,
    pub explorer_result: Option<ExplorerSearchResultSnapshot>,
    pub explorer_loading: bool,
    pub explorer_searching: bool,
    pub explorer_error: Option<String>,
    explorer_search_id: u64,
    pub block_details: Option<BlockDetailsSnapshot>,
    pub block_details_loading: bool,
    pub block_transaction_position: Option<u16>,
    block_return_section: Option<Section>,
    requested_block_transaction_position: Option<u16>,
    pub genesis_enabled: bool,
    pub address_picker_open: bool,
    pub address_operation: Option<AddressOperation>,
    pub address_error: Option<String>,
    pub action: Option<Action>,
    pub send_recipient: String,
    pub send_amount: String,
    pub send_fee: String,
    pub send_in_flight: bool,
    proof_forge_started_at: Option<Instant>,
    pub send_result: Option<PaymentSubmission>,
    pub send_error: Option<String>,
    pub consolidation_plan: Option<ConsolidationPlan>,
    pub consolidation_plan_in_flight: bool,
    pub consolidation_in_flight: bool,
    pub consolidation_result: Option<ConsolidationSubmission>,
    pub consolidation_error: Option<String>,
    pub copied_value: Option<String>,
    pub copied_address: Option<u32>,
    pub editing_address: Option<u32>,
    pub edit_label: String,
    pub selected_utxo_slot: Option<u32>,
    pub utxo_segment_filter: Option<u8>,
    pub utxo_page: usize,
    pub node_settings: NodeSettingsSnapshot,
    pub settings_tab: SettingsTab,
    pub language: Language,
    pub language_selection_required: bool,
    language_forge_started_at: Instant,
    pub settings_data_dir: String,
    pub settings_p2p_listen: String,
    pub settings_seeds: text_editor::Content,
    pub settings_log_level: LogLevel,
    pub settings_applying: bool,
    pub node_log: text_editor::Content,
    pub node_log_loading: bool,
    pub node_log_error: Option<String>,
    pub node_log_paused: bool,
    node_log_last_refresh: Option<Instant>,
    node_log_request_id: u64,
    pub wallet_setup_required: bool,
    pub wallet_setup_mode: WalletSetupMode,
    pub secret_action_in_flight: bool,
    address_discovery_pending: bool,
    address_discovery_in_flight: bool,
    pub secret_dialog: Option<SecretDialog>,
    pub secret_import_mode: SecretImportMode,
    pub secret_photo: Option<PreparedPhoto>,
    pub photo_scan_progress: f32,
    pub photo_scan_active: bool,
    pub photo_key_active: bool,
    photo_scan_last_tick: Option<Instant>,
    photo_scan_velocity: f32,
    photo_scan_completed_at: Option<Instant>,
    pending_photo_import_result: Option<Result<String, String>>,
    pub exported_master_secret: SensitiveString,
    pub imported_master_secret: SensitiveString,
    pub master_secret_copied: bool,
    pub settings_notice: Option<String>,
    pub settings_error: Option<String>,
    pub matrix_b25: MatrixCacheState,
    pub matrix_b255: MatrixCacheState,
    matrix_preparation_id: u64,
    pub consolidation_hint_open: bool,
    pub header_coin_elapsed: Duration,
    consolidation_badge_hovered: bool,
    consolidation_card_hovered: bool,
    consolidation_hint_close_ticks: u8,
    backend: Backend,
    refresh_in_flight: bool,
    ensure_in_flight: bool,
    consecutive_refresh_failures: u8,
    shutting_down: bool,
    shutdown_forge_started_at: Option<Instant>,
    header_coin_last_tick: Instant,
    window_focused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState {
    Mock,
    Starting,
    Online,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Send,
    Consolidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretDialog {
    Export,
    Import,
    Generate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSetupMode {
    Choose,
    Generate,
    Raw,
    Photo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressOperation {
    Create,
    Activate(u32),
}

#[derive(Debug, Clone)]
pub enum Message {
    Navigate(Section),
    ToggleAddressPicker,
    SelectAddress(u32),
    CreateAddress,
    OpenAction(Action),
    CloseAction,
    SendRecipientChanged(String),
    PasteSendRecipient,
    SendRecipientClipboardLoaded(Option<String>),
    SendAmountChanged(String),
    SendFeeChanged(String),
    SubmitSend,
    ProofForgeTick,
    SendFinished(Result<PaymentSubmission, String>),
    ConsolidationPlanned(Result<ConsolidationPlan, String>),
    SubmitConsolidation,
    ConsolidationFinished(Result<ConsolidationSubmission, String>),
    CopyValue(String),
    ResetSend,
    CopyAddress(u32),
    SelectUtxo(u32),
    SelectSegment(u8),
    PreviousUtxoPage,
    NextUtxoPage,
    BeginEditAddress(u32),
    EditAddressLabel(String),
    SaveAddressLabel,
    CancelAddressLabel,
    EnterConsolidationBadge,
    LeaveConsolidationBadge,
    EnterConsolidationCard,
    LeaveConsolidationCard,
    ConsolidationHintCloseTick,
    HeaderCoinTick(Instant),
    WindowFocused(bool),
    EnsureNodeFinished(Result<(), String>),
    RefreshTick,
    SnapshotLoaded(Result<Box<BackendSnapshot>, String>),
    AddressCreated(Result<(), String>),
    AddressActivated(u32, Result<(), String>),
    AddressDiscoveryFinished(Result<String, String>),
    #[cfg(feature = "dev-genesis")]
    ToggleGenesis(bool),
    AdjustMiningThreads(i8),
    SetMining(bool),
    NodeRestarted(Result<(), String>),
    PreviousMiningPage,
    NextMiningPage,
    SetProofsTab(ProofsTab),
    RefreshReceipts,
    ReceiptsLoaded(Result<Box<ReceiptsSnapshot>, String>),
    PreviousReceiptPage,
    NextReceiptPage,
    SelectReceipt(String),
    ReceiptDetailLoaded(String, Result<Box<ReceiptDetailSnapshot>, String>),
    EditReceipt(text_editor::Action),
    PasteReceipt,
    ReceiptClipboardLoaded(Option<String>),
    VerifyReceipt,
    ReceiptVerified(Result<Box<ReceiptVerificationSnapshot>, String>),
    ClearReceiptVerifier,
    RefreshExplorer,
    ExplorerLoaded(Result<Box<ExplorerSnapshot>, String>),
    ExplorerQueryChanged(String),
    SubmitExplorerSearch,
    ClearExplorerSearch,
    ExplorerSearchLoaded(u64, Result<Box<ExplorerLookup>, String>),
    PreviousExplorerBlockPage,
    NextExplorerBlockPage,
    PreviousExplorerTransactionPage,
    NextExplorerTransactionPage,
    PreviousExplorerSlotPage,
    NextExplorerSlotPage,
    OpenBlockDetails(u64),
    OpenLocatedTransaction(u64, u16),
    BlockDetailsLoaded(Result<Box<BlockDetailsSnapshot>, String>),
    OpenBlockTransaction(u16),
    CloseBlockTransaction,
    CloseBlockDetails,
    SettingsDataDirectoryChanged(String),
    SetSettingsTab(SettingsTab),
    SetLanguage(Language),
    LanguageForgeTick,
    ChooseDataDirectory,
    DataDirectoryChosen(Option<std::path::PathBuf>),
    SettingsP2pListenChanged(String),
    EditSettingsSeeds(text_editor::Action),
    SetSettingsLogLevel(LogLevel),
    EditNodeLog(text_editor::Action),
    RefreshNodeLog,
    NodeLogLoaded(u64, Result<String, String>),
    ApplySettings,
    SettingsApplied(Result<(), String>),
    ResetSettings,
    BeginExportSecret,
    ExportSecretFinished(Result<SensitiveString, String>),
    CopyExportedSecret,
    BeginImportSecret,
    BeginPhotoSecret,
    SetWalletSetupMode(WalletSetupMode),
    ChooseSecretPhoto,
    SecretPhotoPrepared(Result<Option<Box<PreparedPhoto>>, String>),
    PhotoScanTick,
    PhotoImportFinished(Result<String, String>),
    ImportSecretChanged(SensitiveString),
    PasteImportSecret,
    ImportSecretClipboardLoaded(Option<SensitiveString>),
    ConfirmImportSecret,
    BeginGenerateSecret,
    ConfirmGenerateSecret,
    CloseSecretDialog,
    ImportSecretFinished(Result<String, String>),
    PrepareMatrices,
    B25MatrixPrepared(u64, Result<(), String>),
    B255MatrixPrepared(u64, Result<(), String>),
    Keyboard(iced::keyboard::Event),
    Noop,
    Exit,
    ShutdownForgeTick,
    ExitReady,
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let backend = Backend::from_env();
        let mock = backend.is_mock();
        let snapshot = if mock {
            AppSnapshot::design_preview()
        } else {
            AppSnapshot::offline(backend.available_threads())
        };
        let node_settings = backend.settings_snapshot();
        let settings_data_dir = node_settings.data_dir.clone();
        let settings_p2p_listen = node_settings.p2p_listen.clone();
        let settings_seeds =
            text_editor::Content::with_text(&node_settings.custom_seeds.join("\n"));
        let settings_log_level = node_settings.log_level;
        let wallet_setup_required = backend.wallet_setup_required();
        let persisted_language = backend.interface_language();
        let language = persisted_language.unwrap_or_default();
        let language_selection_required = persisted_language.is_none() && !mock;
        crate::i18n::activate(language);

        let app = Self {
            snapshot,
            section: Section::Present,
            backend_state: if mock {
                BackendState::Mock
            } else {
                BackendState::Starting
            },
            backend_error: None,
            node_action_in_flight: false,
            mining_page: 1,
            proofs_tab: ProofsTab::Mine,
            receipts: ReceiptsSnapshot::empty(),
            receipt_page: 1,
            receipts_loading: false,
            receipts_loaded_height: None,
            selected_receipt_txid: None,
            receipt_detail: None,
            receipt_detail_loading: false,
            receipt_editor: text_editor::Content::new(),
            receipt_verification: None,
            receipt_verifying: false,
            receipt_error: None,
            explorer: ExplorerSnapshot::empty(),
            explorer_block_page: 1,
            explorer_transaction_page: 1,
            explorer_slot_page: 1,
            explorer_query: String::new(),
            explorer_result: None,
            explorer_loading: false,
            explorer_searching: false,
            explorer_error: None,
            explorer_search_id: 0,
            block_details: None,
            block_details_loading: false,
            block_transaction_position: None,
            block_return_section: None,
            requested_block_transaction_position: None,
            genesis_enabled: false,
            address_picker_open: false,
            address_operation: None,
            address_error: None,
            action: None,
            send_recipient: String::new(),
            send_amount: String::new(),
            send_fee: String::new(),
            send_in_flight: false,
            proof_forge_started_at: None,
            send_result: None,
            send_error: None,
            consolidation_plan: None,
            consolidation_plan_in_flight: false,
            consolidation_in_flight: false,
            consolidation_result: None,
            consolidation_error: None,
            copied_value: None,
            copied_address: None,
            editing_address: None,
            edit_label: String::new(),
            selected_utxo_slot: None,
            utxo_segment_filter: None,
            utxo_page: 1,
            node_settings,
            settings_tab: SettingsTab::Secret,
            language,
            language_selection_required,
            language_forge_started_at: Instant::now(),
            settings_data_dir,
            settings_p2p_listen,
            settings_seeds,
            settings_log_level,
            settings_applying: false,
            node_log: text_editor::Content::new(),
            node_log_loading: false,
            node_log_error: None,
            node_log_paused: false,
            node_log_last_refresh: None,
            node_log_request_id: 0,
            wallet_setup_required,
            wallet_setup_mode: WalletSetupMode::Choose,
            secret_action_in_flight: false,
            address_discovery_pending: false,
            address_discovery_in_flight: false,
            secret_dialog: None,
            secret_import_mode: SecretImportMode::Raw,
            secret_photo: None,
            photo_scan_progress: 1.0,
            photo_scan_active: false,
            photo_key_active: false,
            photo_scan_last_tick: None,
            photo_scan_velocity: 0.0,
            photo_scan_completed_at: None,
            pending_photo_import_result: None,
            exported_master_secret: SensitiveString::default(),
            imported_master_secret: SensitiveString::default(),
            master_secret_copied: false,
            settings_notice: None,
            settings_error: None,
            matrix_b25: if mock {
                MatrixCacheState::Ready
            } else {
                MatrixCacheState::Pending
            },
            matrix_b255: if mock {
                MatrixCacheState::Ready
            } else {
                MatrixCacheState::Pending
            },
            matrix_preparation_id: 0,
            consolidation_hint_open: false,
            header_coin_elapsed: Duration::ZERO,
            consolidation_badge_hovered: false,
            consolidation_card_hovered: false,
            consolidation_hint_close_ticks: 0,
            backend: backend.clone(),
            refresh_in_flight: false,
            ensure_in_flight: !mock && !wallet_setup_required,
            consecutive_refresh_failures: 0,
            shutting_down: false,
            shutdown_forge_started_at: None,
            header_coin_last_tick: Instant::now(),
            window_focused: true,
        };
        let task = if mock || wallet_setup_required {
            Task::none()
        } else {
            Task::perform(
                async move { backend.ensure_running().await },
                Message::EnsureNodeFinished,
            )
        };
        (app, task)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Navigate(section) => {
                if self.secret_action_in_flight
                    || self.photo_scan_active
                    || self.address_operation.is_some()
                    || self.wallet_action_in_flight()
                {
                    return Task::none();
                }
                if section != Section::Explorer {
                    self.explorer_search_id = self.explorer_search_id.wrapping_add(1);
                    self.explorer_searching = false;
                }
                self.section = section;
                self.address_picker_open = false;
                self.action = None;
                self.editing_address = None;
                self.block_details = None;
                self.block_transaction_position = None;
                self.block_return_section = None;
                self.requested_block_transaction_position = None;
                self.close_consolidation_hint();
                if section == Section::Explorer {
                    return self.refresh_explorer_view();
                }
                if section == Section::Proofs {
                    return self.refresh_receipts_view();
                }
                if section == Section::Settings && self.settings_tab == SettingsTab::Node {
                    self.resume_node_log();
                    return self.refresh_node_log();
                }
            }
            Message::ToggleAddressPicker => {
                if self.wallet_action_in_flight()
                    || (self.address_picker_open && self.address_operation.is_some())
                {
                    return Task::none();
                }
                self.address_picker_open = !self.address_picker_open;
                if self.address_picker_open {
                    self.action = None;
                    self.block_details = None;
                    self.block_transaction_position = None;
                    self.address_error = None;
                }
                self.editing_address = None;
                self.close_consolidation_hint();
            }
            Message::SelectAddress(key_index) => {
                if self.wallet_action_in_flight()
                    || self.address_operation.is_some()
                    || !matches!(
                        self.backend_state,
                        BackendState::Online | BackendState::Mock
                    )
                    || key_index == self.snapshot.active_address().key_index
                {
                    return Task::none();
                }
                self.address_error = None;
                self.close_consolidation_hint();
                if self.backend.is_mock() {
                    self.snapshot.activate_address(key_index);
                    self.address_picker_open = false;
                    self.copied_address = None;
                    self.selected_utxo_slot = None;
                    self.utxo_segment_filter = None;
                    self.utxo_page = 1;
                } else {
                    self.address_operation = Some(AddressOperation::Activate(key_index));
                    let backend = self.backend.clone();
                    return Task::perform(
                        async move { backend.set_active_address(key_index).await },
                        move |result| Message::AddressActivated(key_index, result),
                    );
                }
            }
            Message::CreateAddress => {
                if self.wallet_action_in_flight()
                    || self.address_operation.is_some()
                    || !matches!(
                        self.backend_state,
                        BackendState::Online | BackendState::Mock
                    )
                {
                    return Task::none();
                }
                self.address_error = None;
                self.close_consolidation_hint();
                if self.backend.is_mock() {
                    self.snapshot.create_preview_address();
                } else {
                    self.address_operation = Some(AddressOperation::Create);
                    let backend = self.backend.clone();
                    return Task::perform(
                        async move { backend.create_address().await },
                        Message::AddressCreated,
                    );
                }
            }
            Message::OpenAction(action) => {
                if self.address_operation.is_some() || self.wallet_action_in_flight() {
                    return Task::none();
                }
                self.action = Some(action);
                self.address_picker_open = false;
                self.block_details = None;
                self.block_transaction_position = None;
                self.close_consolidation_hint();
                self.proof_forge_started_at = None;
                if action == Action::Send {
                    self.send_result = None;
                    self.send_error = None;
                    return Task::none();
                }

                self.consolidation_plan = None;
                self.consolidation_result = None;
                self.consolidation_error = None;
                if !matches!(
                    self.backend_state,
                    BackendState::Online | BackendState::Mock
                ) {
                    self.consolidation_error =
                        Some("The wallet must be online to calculate the transaction.".into());
                    return Task::none();
                }
                self.consolidation_plan_in_flight = true;
                let backend = self.backend.clone();
                return Task::perform(
                    async move { backend.plan_consolidation().await },
                    Message::ConsolidationPlanned,
                );
            }
            Message::CloseAction => {
                if !self.wallet_action_in_flight() {
                    self.action = None;
                    self.proof_forge_started_at = None;
                    self.send_result = None;
                    self.send_error = None;
                    self.consolidation_plan = None;
                    self.consolidation_result = None;
                    self.consolidation_error = None;
                }
            }
            Message::SendRecipientChanged(recipient) => {
                if !self.send_in_flight {
                    self.send_recipient = recipient;
                    self.send_result = None;
                    self.send_error = None;
                }
            }
            Message::PasteSendRecipient => {
                if self.send_in_flight || self.action != Some(Action::Send) {
                    return Task::none();
                }
                return iced::clipboard::read().map(Message::SendRecipientClipboardLoaded);
            }
            Message::SendRecipientClipboardLoaded(contents) => {
                if self.send_in_flight || self.action != Some(Action::Send) {
                    return Task::none();
                }
                let recipient = contents.map(|contents| {
                    contents
                        .chars()
                        .filter(|character| !character.is_ascii_whitespace())
                        .collect::<String>()
                });
                if let Some(recipient) = recipient.filter(|recipient| !recipient.is_empty()) {
                    self.send_recipient = recipient;
                    self.send_result = None;
                    self.send_error = None;
                } else {
                    self.send_error = Some("Clipboard does not contain text.".into());
                }
            }
            Message::SendAmountChanged(amount) => {
                if !self.send_in_flight {
                    self.send_amount = amount;
                    self.send_result = None;
                    self.send_error = None;
                }
            }
            Message::SendFeeChanged(fee) => {
                if !self.send_in_flight {
                    self.send_fee = fee;
                    self.send_result = None;
                    self.send_error = None;
                }
            }
            Message::SubmitSend => {
                if self.send_in_flight
                    || !matches!(
                        self.backend_state,
                        BackendState::Online | BackendState::Mock
                    )
                {
                    return Task::none();
                }
                let recipient = self.send_recipient.trim().to_owned();
                if recipient.is_empty() {
                    self.send_error = Some("Enter a recipient address.".into());
                    return Task::none();
                }
                let amount_micronoid = match parse_noid_amount(&self.send_amount) {
                    Ok(amount) => amount,
                    Err(error) => {
                        self.send_error = Some(error);
                        return Task::none();
                    }
                };
                let fee_micronoid = match parse_optional_noid_fee(&self.send_fee) {
                    Ok(fee) => fee,
                    Err(error) => {
                        self.send_error = Some(error);
                        return Task::none();
                    }
                };
                self.send_in_flight = true;
                self.proof_forge_started_at = Some(Instant::now());
                self.send_result = None;
                self.send_error = None;
                let backend = self.backend.clone();
                return Task::perform(
                    async move {
                        backend
                            .send_payment(recipient, amount_micronoid, fee_micronoid)
                            .await
                    },
                    Message::SendFinished,
                );
            }
            Message::ProofForgeTick => {}
            Message::SendFinished(result) => {
                self.send_in_flight = false;
                self.proof_forge_started_at = None;
                match result {
                    Ok(submission) => {
                        self.send_result = Some(submission);
                        self.send_amount.clear();
                        self.send_fee.clear();
                        return self.refresh_snapshot();
                    }
                    Err(error) => self.send_error = Some(error),
                }
            }
            Message::ConsolidationPlanned(result) => {
                self.consolidation_plan_in_flight = false;
                if self.action != Some(Action::Consolidate) {
                    return Task::none();
                }
                match result {
                    Ok(plan) => {
                        self.consolidation_plan = Some(plan);
                        self.consolidation_error = None;
                    }
                    Err(error) => {
                        self.consolidation_plan = None;
                        self.consolidation_error = Some(error);
                    }
                }
            }
            Message::SubmitConsolidation => {
                if self.consolidation_in_flight
                    || self.consolidation_plan_in_flight
                    || self.consolidation_plan.is_none()
                    || self.action != Some(Action::Consolidate)
                    || !matches!(
                        self.backend_state,
                        BackendState::Online | BackendState::Mock
                    )
                {
                    return Task::none();
                }
                self.consolidation_in_flight = true;
                self.proof_forge_started_at = Some(Instant::now());
                self.consolidation_result = None;
                self.consolidation_error = None;
                let backend = self.backend.clone();
                let plan = self
                    .consolidation_plan
                    .as_ref()
                    .expect("consolidation plan checked above")
                    .clone();
                return Task::perform(
                    async move { backend.consolidate(plan).await },
                    Message::ConsolidationFinished,
                );
            }
            Message::ConsolidationFinished(result) => {
                self.consolidation_in_flight = false;
                self.proof_forge_started_at = None;
                if self.action != Some(Action::Consolidate) {
                    return Task::none();
                }
                match result {
                    Ok(submission) => {
                        self.consolidation_result = Some(submission);
                        self.consolidation_error = None;
                        return self.refresh_snapshot();
                    }
                    Err(error) => {
                        self.consolidation_plan = None;
                        self.consolidation_error = Some(error);
                    }
                }
            }
            Message::CopyValue(value) => {
                self.copied_value = Some(value.clone());
                return iced::clipboard::write(value);
            }
            Message::ResetSend => {
                if !self.send_in_flight {
                    self.send_result = None;
                    self.send_error = None;
                }
            }
            Message::CopyAddress(key_index) => {
                if let Some(address) = self
                    .snapshot
                    .addresses
                    .iter()
                    .find(|address| address.key_index == key_index)
                {
                    self.copied_address = Some(key_index);
                    self.copied_value = Some(address.address.clone());
                    return iced::clipboard::write(address.address.clone());
                }
            }
            Message::SelectUtxo(slot_index) => {
                if self
                    .snapshot
                    .utxos
                    .iter()
                    .any(|utxo| utxo.slot_index == slot_index)
                {
                    self.selected_utxo_slot = Some(slot_index);
                }
            }
            Message::SelectSegment(segment) => {
                let owned = self
                    .snapshot
                    .utxos
                    .iter()
                    .any(|utxo| utxo.segment == segment);
                if owned {
                    self.utxo_segment_filter =
                        (self.utxo_segment_filter != Some(segment)).then_some(segment);
                    self.selected_utxo_slot = None;
                    self.utxo_page = 1;
                }
            }
            Message::PreviousUtxoPage => {
                if self.utxo_page > 1 {
                    self.utxo_page -= 1;
                    self.selected_utxo_slot = None;
                }
            }
            Message::NextUtxoPage => {
                if self.utxo_page < self.utxo_page_count() {
                    self.utxo_page += 1;
                    self.selected_utxo_slot = None;
                }
            }
            Message::BeginEditAddress(key_index) => {
                if let Some(address) = self
                    .snapshot
                    .addresses
                    .iter()
                    .find(|address| address.key_index == key_index)
                {
                    self.editing_address = Some(key_index);
                    self.edit_label = address.label.clone();
                }
            }
            Message::EditAddressLabel(label) => self.edit_label = label,
            Message::SaveAddressLabel => {
                if let Some(key_index) = self.editing_address {
                    self.snapshot.rename_address(key_index, &self.edit_label);
                }
                self.editing_address = None;
                self.edit_label.clear();
            }
            Message::CancelAddressLabel => {
                self.editing_address = None;
                self.edit_label.clear();
            }
            Message::EnterConsolidationBadge => {
                if self.consolidation_recommended() {
                    self.consolidation_hint_open = true;
                    self.consolidation_badge_hovered = true;
                    self.consolidation_hint_close_ticks = 0;
                }
            }
            Message::LeaveConsolidationBadge => {
                self.consolidation_badge_hovered = false;
                if !self.consolidation_card_hovered {
                    self.consolidation_hint_close_ticks = 4;
                }
            }
            Message::EnterConsolidationCard => {
                self.consolidation_hint_open = true;
                self.consolidation_card_hovered = true;
                self.consolidation_hint_close_ticks = 0;
            }
            Message::LeaveConsolidationCard => {
                self.consolidation_card_hovered = false;
                if !self.consolidation_badge_hovered {
                    self.consolidation_hint_close_ticks = 4;
                }
            }
            Message::ConsolidationHintCloseTick => {
                if !self.consolidation_badge_hovered
                    && !self.consolidation_card_hovered
                    && self.consolidation_hint_close_ticks > 0
                {
                    self.consolidation_hint_close_ticks -= 1;
                    if self.consolidation_hint_close_ticks == 0 {
                        self.consolidation_hint_open = false;
                    }
                }
            }
            Message::HeaderCoinTick(now) => {
                if self.window_focused {
                    self.header_coin_elapsed +=
                        now.saturating_duration_since(self.header_coin_last_tick);
                }
                self.header_coin_last_tick = now;
            }
            Message::WindowFocused(focused) => {
                self.window_focused = focused;
                self.header_coin_last_tick = Instant::now();
            }
            Message::EnsureNodeFinished(result) => {
                self.ensure_in_flight = false;
                match result {
                    Ok(()) => {
                        self.backend_state = BackendState::Online;
                        self.backend_error = None;
                        return Task::batch([
                            self.refresh_snapshot(),
                            self.begin_matrix_preparation(),
                        ]);
                    }
                    Err(error) => {
                        self.backend_state = BackendState::Offline;
                        self.backend_error = Some(error);
                    }
                }
            }
            Message::RefreshTick => {
                let refresh_snapshot = self.snapshot_refresh_available();
                let refresh_node_log = self.node_log_refresh_due();
                return Task::batch([
                    if refresh_snapshot {
                        self.refresh_snapshot()
                    } else {
                        Task::none()
                    },
                    if refresh_node_log {
                        self.refresh_node_log()
                    } else {
                        Task::none()
                    },
                ]);
            }
            Message::SnapshotLoaded(result) => {
                self.refresh_in_flight = false;
                match result {
                    Ok(live) => {
                        let mut live = *live;
                        let previous_height = self.snapshot.network.height;
                        let previous_synced = self.snapshot.network.synced;
                        let previous_state_root = self.snapshot.network.state_root.clone();
                        let returned_mining_page = live.snapshot.mined_blocks.page;
                        live.snapshot.preserve_local_labels_from(&self.snapshot);
                        let selected_still_exists = self.selected_utxo_slot.is_some_and(|slot| {
                            live.snapshot
                                .utxos
                                .iter()
                                .any(|utxo| utxo.slot_index == slot)
                        });
                        let filter_still_exists = self.utxo_segment_filter.is_some_and(|segment| {
                            live.snapshot
                                .utxos
                                .iter()
                                .any(|utxo| utxo.segment == segment)
                        });
                        let filter_removed =
                            self.utxo_segment_filter.is_some() && !filter_still_exists;
                        self.snapshot = live.snapshot;
                        if !selected_still_exists {
                            self.selected_utxo_slot = None;
                        }
                        if filter_removed {
                            self.utxo_segment_filter = None;
                        }
                        self.utxo_page = normalize_utxo_page_after_refresh(
                            self.utxo_page,
                            self.utxo_page_count(),
                            filter_removed,
                        );
                        self.backend_state = BackendState::Online;
                        if self.snapshot.network.synced {
                            self.header_coin_elapsed = Duration::ZERO;
                        } else if previous_synced {
                            self.header_coin_elapsed = Duration::ZERO;
                            self.header_coin_last_tick = Instant::now();
                        }
                        self.backend_error = None;
                        self.consecutive_refresh_failures = 0;
                        if self.snapshot.mined_blocks.total_pages > 0
                            && self.mining_page > self.snapshot.mined_blocks.total_pages
                        {
                            self.mining_page = self.snapshot.mined_blocks.total_pages;
                            return self.refresh_snapshot();
                        }
                        if returned_mining_page != self.mining_page {
                            return self.refresh_snapshot();
                        }
                        if self.address_discovery_pending
                            && !self.address_discovery_in_flight
                            && self.snapshot.network.synced
                        {
                            self.address_discovery_in_flight = true;
                            let backend = self.backend.clone();
                            return Task::perform(
                                async move { backend.discover_owner_addresses().await },
                                Message::AddressDiscoveryFinished,
                            );
                        }
                        if self.section == Section::Explorer
                            && !self.explorer_loading
                            && (self.explorer.blocks.is_empty()
                                || self.explorer.tip_height != self.snapshot.network.height
                                || previous_state_root != self.snapshot.network.state_root)
                        {
                            return self.refresh_explorer_view();
                        }
                        if self.section == Section::Proofs
                            && !self.receipts_loading
                            && (previous_height != self.snapshot.network.height
                                || self.receipts_loaded_height
                                    != Some(self.snapshot.network.height))
                        {
                            return self.refresh_receipts_view();
                        }
                    }
                    Err(error) => {
                        self.backend_error = Some(error);
                        let should_probe = record_snapshot_refresh_failure(
                            &mut self.backend_state,
                            &mut self.consecutive_refresh_failures,
                        );
                        if should_probe && !self.ensure_in_flight {
                            self.ensure_in_flight = true;
                            let backend = self.backend.clone();
                            return Task::perform(
                                async move { backend.ensure_running().await },
                                Message::EnsureNodeFinished,
                            );
                        }
                    }
                }
            }
            Message::AddressCreated(result) => {
                self.address_operation = None;
                match result {
                    Ok(()) => return self.refresh_snapshot(),
                    Err(error) => self.address_error = Some(error),
                }
            }
            Message::AddressActivated(key_index, result) => {
                if self.address_operation != Some(AddressOperation::Activate(key_index)) {
                    return Task::none();
                }
                self.address_operation = None;
                match result {
                    Ok(()) => {
                        self.address_picker_open = false;
                        self.copied_address = None;
                        self.selected_utxo_slot = None;
                        self.utxo_segment_filter = None;
                        self.utxo_page = 1;
                        return self.refresh_snapshot();
                    }
                    Err(error) => self.address_error = Some(error),
                }
            }
            Message::AddressDiscoveryFinished(result) => {
                self.address_discovery_in_flight = false;
                self.address_discovery_pending = false;
                match result {
                    Ok(_) => {
                        self.settings_notice = None;
                        return self.refresh_snapshot();
                    }
                    Err(error) => {
                        self.settings_error =
                            Some(format!("Automatic address discovery failed: {error}"));
                    }
                }
            }
            #[cfg(feature = "dev-genesis")]
            Message::ToggleGenesis(enabled) => {
                if !self.snapshot.mining.enabled && !self.node_action_in_flight {
                    self.genesis_enabled = enabled;
                }
            }
            Message::AdjustMiningThreads(delta) => {
                if !self.snapshot.mining.enabled && !self.node_action_in_flight {
                    let available = self.snapshot.mining.available_threads.max(1);
                    let selected = self.snapshot.mining.selected_threads.max(1);
                    let next = if delta.is_negative() {
                        selected.saturating_sub(delta.unsigned_abs() as usize)
                    } else {
                        selected.saturating_add(delta as usize)
                    }
                    .clamp(1, available);
                    self.snapshot.mining.selected_threads = next;
                    self.backend.set_selected_threads(next);
                }
            }
            Message::SetMining(enabled) => {
                if self.node_action_in_flight
                    || self.wallet_action_in_flight()
                    || self.address_operation.is_some()
                    || self.snapshot.mining.enabled == enabled
                {
                    return Task::none();
                }
                if enabled && self.matrix_b25 != MatrixCacheState::Ready {
                    return Task::none();
                }
                if self.backend.is_mock() {
                    self.snapshot.mining.enabled = enabled;
                    self.snapshot.mining.ready = enabled;
                    self.snapshot.mining.isolated = enabled && self.genesis_enabled;
                    return Task::none();
                }
                let genesis = enabled && self.genesis_enabled && cfg!(feature = "dev-genesis");
                let mode = if enabled {
                    NodeMode::Miner
                } else {
                    NodeMode::Node
                };
                let selected_threads = self.snapshot.mining.selected_threads;
                self.node_action_in_flight = true;
                self.backend_state = BackendState::Starting;
                self.backend_error = None;
                let backend = self.backend.clone();
                return Task::perform(
                    async move { backend.restart(mode, selected_threads, genesis).await },
                    Message::NodeRestarted,
                );
            }
            Message::NodeRestarted(result) => {
                self.node_action_in_flight = false;
                match result {
                    Ok(()) => {
                        self.backend_state = BackendState::Online;
                        return self.refresh_snapshot();
                    }
                    Err(error) => {
                        self.backend_state = BackendState::Offline;
                        self.backend_error = Some(error);
                    }
                }
            }
            Message::PreviousMiningPage => {
                if self.mining_page > 1 {
                    self.mining_page -= 1;
                    if self.backend.is_mock() {
                        self.snapshot.set_preview_mining_page(self.mining_page);
                    } else {
                        return self.refresh_snapshot();
                    }
                }
            }
            Message::NextMiningPage => {
                let last_page = self.snapshot.mined_blocks.total_pages.max(1);
                if self.mining_page < last_page {
                    self.mining_page += 1;
                    if self.backend.is_mock() {
                        self.snapshot.set_preview_mining_page(self.mining_page);
                    } else {
                        return self.refresh_snapshot();
                    }
                }
            }
            Message::SetProofsTab(tab) => {
                self.proofs_tab = tab;
                self.receipt_error = None;
                if tab == ProofsTab::Mine && self.receipts_loaded_height.is_none() {
                    return self.refresh_receipts_view();
                }
            }
            Message::RefreshReceipts => return self.refresh_receipts_view(),
            Message::ReceiptsLoaded(result) => {
                self.receipts_loading = false;
                if self.section != Section::Proofs {
                    return Task::none();
                }
                match result {
                    Ok(receipts) => {
                        self.receipts = *receipts;
                        self.receipt_page = self.receipts.page;
                        self.receipts_loaded_height = Some(self.snapshot.network.height);
                        self.receipt_error = None;
                        let selected_is_visible =
                            self.selected_receipt_txid.as_ref().is_some_and(|selected| {
                                self.receipts
                                    .receipts
                                    .iter()
                                    .any(|receipt| &receipt.txid == selected)
                            });
                        if !selected_is_visible {
                            self.selected_receipt_txid = self
                                .receipts
                                .receipts
                                .first()
                                .map(|receipt| receipt.txid.clone());
                            self.receipt_detail = None;
                        }
                        if let Some(txid) = self.selected_receipt_txid.clone() {
                            if self.receipt_detail.as_ref().is_none_or(|detail| {
                                detail
                                    .verification
                                    .authenticated_summary
                                    .as_ref()
                                    .is_none_or(|summary| summary.txid != txid)
                            }) {
                                return self.load_receipt_detail(txid);
                            }
                        } else {
                            self.receipt_detail = None;
                            self.receipt_detail_loading = false;
                        }
                    }
                    Err(error) => self.receipt_error = Some(error),
                }
            }
            Message::PreviousReceiptPage => {
                if !self.receipts_loading && self.receipt_page > 1 {
                    self.receipt_page -= 1;
                    self.selected_receipt_txid = None;
                    self.receipt_detail = None;
                    return self.refresh_receipts_view();
                }
            }
            Message::NextReceiptPage => {
                let last = self.receipts.total_pages.max(1);
                if !self.receipts_loading && self.receipt_page < last {
                    self.receipt_page += 1;
                    self.selected_receipt_txid = None;
                    self.receipt_detail = None;
                    return self.refresh_receipts_view();
                }
            }
            Message::SelectReceipt(txid) => {
                if !self.receipt_detail_loading
                    && self
                        .receipts
                        .receipts
                        .iter()
                        .any(|receipt| receipt.txid == txid)
                {
                    self.selected_receipt_txid = Some(txid.clone());
                    self.receipt_detail = None;
                    self.receipt_error = None;
                    return self.load_receipt_detail(txid);
                }
            }
            Message::ReceiptDetailLoaded(txid, result) => {
                self.receipt_detail_loading = false;
                if self.selected_receipt_txid.as_deref() != Some(txid.as_str()) {
                    return Task::none();
                }
                match result {
                    Ok(detail) => {
                        self.receipt_detail = Some(*detail);
                        self.receipt_error = None;
                    }
                    Err(error) => {
                        self.receipt_detail = None;
                        self.receipt_error = Some(error);
                    }
                }
            }
            Message::EditReceipt(action) => {
                if !self.receipt_verifying {
                    self.receipt_editor.perform(action);
                    self.receipt_verification = None;
                    self.receipt_error = None;
                }
            }
            Message::PasteReceipt => {
                if !self.receipt_verifying {
                    return iced::clipboard::read().map(Message::ReceiptClipboardLoaded);
                }
            }
            Message::ReceiptClipboardLoaded(contents) => {
                if let Some(contents) = contents {
                    self.receipt_editor = text_editor::Content::with_text(&contents);
                    self.receipt_verification = None;
                    self.receipt_error = None;
                } else {
                    self.receipt_error = Some("Clipboard does not contain text.".into());
                }
            }
            Message::VerifyReceipt => {
                if self.receipt_verifying {
                    return Task::none();
                }
                self.receipt_verifying = true;
                self.receipt_verification = None;
                self.receipt_error = None;
                let backend = self.backend.clone();
                let receipt = self.receipt_editor.text();
                return Task::perform(
                    async move { backend.verify_receipt(receipt).await.map(Box::new) },
                    Message::ReceiptVerified,
                );
            }
            Message::ReceiptVerified(result) => {
                self.receipt_verifying = false;
                match result {
                    Ok(verification) => {
                        self.receipt_verification = Some(*verification);
                        self.receipt_error = None;
                    }
                    Err(error) => {
                        self.receipt_verification = None;
                        self.receipt_error = Some(error);
                    }
                }
            }
            Message::ClearReceiptVerifier => {
                if !self.receipt_verifying {
                    self.receipt_editor = text_editor::Content::new();
                    self.receipt_verification = None;
                    self.receipt_error = None;
                }
            }
            Message::RefreshExplorer => return self.refresh_explorer_view(),
            Message::ExplorerLoaded(result) => {
                self.explorer_loading = false;
                match result {
                    Ok(explorer) => {
                        self.explorer = *explorer;
                        self.explorer_block_page = self.explorer.block_page;
                        self.explorer_transaction_page = self.explorer.recent_transactions.page;
                        self.explorer_error = None;
                    }
                    Err(error) => self.explorer_error = Some(error),
                }
            }
            Message::ExplorerQueryChanged(query) => {
                if !self.explorer_searching {
                    self.explorer_query = query;
                    self.explorer_error = None;
                }
            }
            Message::SubmitExplorerSearch => {
                self.explorer_transaction_page = 1;
                self.explorer_slot_page = 1;
                self.explorer_result = None;
                return self.search_explorer();
            }
            Message::ClearExplorerSearch => {
                self.explorer_search_id = self.explorer_search_id.wrapping_add(1);
                self.explorer_searching = false;
                self.explorer_query.clear();
                self.explorer_result = None;
                self.explorer_error = None;
                self.explorer_transaction_page = 1;
                self.explorer_slot_page = 1;
            }
            Message::ExplorerSearchLoaded(search_id, result) => {
                if search_id != self.explorer_search_id || self.section != Section::Explorer {
                    return Task::none();
                }
                self.explorer_searching = false;
                match result {
                    Ok(lookup) => {
                        self.explorer_error = None;
                        match *lookup {
                            ExplorerLookup::Result(result) => {
                                if let ExplorerSearchResultSnapshot::Address(address) = &result {
                                    self.explorer_transaction_page =
                                        address.recent_transactions.page;
                                    let slot_pages = address
                                        .slots
                                        .len()
                                        .div_ceil(EXPLORER_SLOT_PAGE_SIZE)
                                        .max(1);
                                    self.explorer_slot_page =
                                        self.explorer_slot_page.clamp(1, slot_pages);
                                }
                                self.explorer_result = Some(result);
                            }
                            ExplorerLookup::Block(details) => {
                                self.explorer_result = None;
                                self.block_transaction_position = None;
                                self.block_details = Some(details);
                                return iced::widget::operation::snap_to(
                                    BLOCK_DETAILS_SCROLL_ID,
                                    iced::widget::operation::RelativeOffset::START,
                                );
                            }
                            ExplorerLookup::Transaction { position, details } => {
                                self.explorer_result = None;
                                self.block_transaction_position = Some(position);
                                self.block_details = Some(details);
                                return iced::widget::operation::snap_to(
                                    TRANSACTION_DETAILS_SCROLL_ID,
                                    iced::widget::operation::RelativeOffset::START,
                                );
                            }
                        }
                    }
                    Err(error) => self.explorer_error = Some(error),
                }
            }
            Message::PreviousExplorerBlockPage => {
                if !self.explorer_loading && self.explorer_block_page > 1 {
                    self.explorer_block_page -= 1;
                    return self.load_explorer();
                }
            }
            Message::NextExplorerBlockPage => {
                let last = self.explorer.block_total_pages.max(1);
                if !self.explorer_loading && self.explorer_block_page < last {
                    self.explorer_block_page += 1;
                    return self.load_explorer();
                }
            }
            Message::PreviousExplorerTransactionPage => {
                if !self.explorer_searching
                    && !self.explorer_loading
                    && self.explorer_transaction_page > 1
                {
                    self.explorer_transaction_page -= 1;
                    return if matches!(
                        self.explorer_result,
                        Some(ExplorerSearchResultSnapshot::Address(_))
                    ) {
                        self.search_explorer()
                    } else {
                        self.load_explorer()
                    };
                }
            }
            Message::NextExplorerTransactionPage => {
                let last = match &self.explorer_result {
                    Some(ExplorerSearchResultSnapshot::Address(address)) => {
                        address.recent_transactions.total_pages.max(1)
                    }
                    _ => self.explorer.recent_transactions.total_pages.max(1),
                };
                if !self.explorer_searching
                    && !self.explorer_loading
                    && self.explorer_transaction_page < last
                {
                    self.explorer_transaction_page += 1;
                    return if matches!(
                        self.explorer_result,
                        Some(ExplorerSearchResultSnapshot::Address(_))
                    ) {
                        self.search_explorer()
                    } else {
                        self.load_explorer()
                    };
                }
            }
            Message::PreviousExplorerSlotPage => {
                if self.explorer_slot_page > 1 {
                    self.explorer_slot_page -= 1;
                }
            }
            Message::NextExplorerSlotPage => {
                if let Some(ExplorerSearchResultSnapshot::Address(address)) = &self.explorer_result
                {
                    let total_pages = address.slots.len().div_ceil(EXPLORER_SLOT_PAGE_SIZE).max(1);
                    if self.explorer_slot_page < total_pages {
                        self.explorer_slot_page += 1;
                    }
                }
            }
            Message::OpenBlockDetails(height) => {
                if self.block_details_loading {
                    return Task::none();
                }
                if self.section != Section::Explorer {
                    self.block_return_section = Some(self.section);
                    self.section = Section::Explorer;
                }
                self.block_details_loading = true;
                self.block_transaction_position = None;
                self.requested_block_transaction_position = None;
                self.action = None;
                self.address_picker_open = false;
                self.backend_error = None;
                let backend = self.backend.clone();
                return Task::perform(
                    async move { backend.block_details(height).await.map(Box::new) },
                    Message::BlockDetailsLoaded,
                );
            }
            Message::OpenLocatedTransaction(height, position) => {
                if self.block_details_loading {
                    return Task::none();
                }
                if self.section != Section::Explorer {
                    self.block_return_section = Some(self.section);
                    self.section = Section::Explorer;
                }
                self.block_details_loading = true;
                self.block_transaction_position = None;
                self.requested_block_transaction_position = Some(position);
                self.action = None;
                self.address_picker_open = false;
                self.backend_error = None;
                let backend = self.backend.clone();
                return Task::perform(
                    async move { backend.block_details(height).await.map(Box::new) },
                    Message::BlockDetailsLoaded,
                );
            }
            Message::BlockDetailsLoaded(result) => {
                self.block_details_loading = false;
                if self.section != Section::Explorer {
                    self.requested_block_transaction_position = None;
                    return Task::none();
                }
                match result {
                    Ok(details) => {
                        self.block_details = Some(*details);
                        if let Some(position) = self.requested_block_transaction_position.take() {
                            let exists = self
                                .block_details
                                .as_ref()
                                .and_then(|details| details.retained.as_ref())
                                .is_some_and(|retained| {
                                    retained
                                        .transactions
                                        .iter()
                                        .any(|transaction| transaction.position == position)
                                });
                            if exists {
                                self.block_transaction_position = Some(position);
                                return iced::widget::operation::snap_to(
                                    TRANSACTION_DETAILS_SCROLL_ID,
                                    iced::widget::operation::RelativeOffset::START,
                                );
                            }
                        }
                        return iced::widget::operation::snap_to(
                            BLOCK_DETAILS_SCROLL_ID,
                            iced::widget::operation::RelativeOffset::START,
                        );
                    }
                    Err(error) => {
                        self.backend_error = Some(error);
                    }
                }
            }
            Message::OpenBlockTransaction(position) => {
                let exists = self
                    .block_details
                    .as_ref()
                    .and_then(|details| details.retained.as_ref())
                    .is_some_and(|retained| {
                        retained
                            .transactions
                            .iter()
                            .any(|transaction| transaction.position == position)
                    });
                if exists {
                    self.block_transaction_position = Some(position);
                    return iced::widget::operation::snap_to(
                        TRANSACTION_DETAILS_SCROLL_ID,
                        iced::widget::operation::RelativeOffset::START,
                    );
                }
            }
            Message::CloseBlockTransaction => self.block_transaction_position = None,
            Message::CloseBlockDetails => {
                self.block_details = None;
                self.block_transaction_position = None;
                self.requested_block_transaction_position = None;
                if let Some(section) = self.block_return_section.take() {
                    self.section = section;
                }
            }
            Message::SetSettingsTab(tab) => {
                if !self.settings_applying
                    && !self.secret_action_in_flight
                    && !self.photo_scan_active
                {
                    self.settings_tab = tab;
                    self.settings_notice = None;
                    self.settings_error = None;
                    if tab == SettingsTab::Node {
                        self.resume_node_log();
                        return self.refresh_node_log();
                    }
                }
            }
            Message::SetLanguage(language) => {
                self.language = language;
                self.language_selection_required = false;
                crate::i18n::activate(language);
                self.settings_notice = None;
                self.settings_error = self.backend.persist_interface_language(language).err();
            }
            Message::LanguageForgeTick => {}
            Message::SettingsDataDirectoryChanged(path) => {
                if !self.settings_applying {
                    self.settings_data_dir = path;
                    self.settings_notice = None;
                    self.settings_error = None;
                }
            }
            Message::ChooseDataDirectory => {
                if self.settings_applying || self.secret_action_in_flight {
                    return Task::none();
                }
                let current = std::path::PathBuf::from(self.settings_data_dir.trim());
                return Task::perform(
                    async move {
                        let mut dialog =
                            rfd::AsyncFileDialog::new().set_title("Node data directory");
                        if current.is_dir() {
                            dialog = dialog.set_directory(current);
                        }
                        dialog
                            .pick_folder()
                            .await
                            .map(|handle| handle.path().to_path_buf())
                    },
                    Message::DataDirectoryChosen,
                );
            }
            Message::DataDirectoryChosen(path) => {
                if let Some(path) = path {
                    self.settings_data_dir = path.display().to_string();
                    self.settings_notice = None;
                    self.settings_error = None;
                }
            }
            Message::SettingsP2pListenChanged(listen) => {
                if !self.settings_applying {
                    self.settings_p2p_listen = listen;
                    self.settings_notice = None;
                    self.settings_error = None;
                }
            }
            Message::EditSettingsSeeds(action) => {
                if !self.settings_applying {
                    self.settings_seeds.perform(action);
                    self.settings_notice = None;
                    self.settings_error = None;
                }
            }
            Message::SetSettingsLogLevel(level) => {
                if !self.settings_applying {
                    self.settings_log_level = level;
                    self.settings_notice = None;
                    self.settings_error = None;
                }
            }
            Message::EditNodeLog(action) => {
                if !action.is_edit() {
                    self.node_log_paused = true;
                    self.node_log.perform(action);
                }
            }
            Message::RefreshNodeLog => {
                if self.node_log_visible() && !self.node_log_loading {
                    self.resume_node_log();
                    return self.refresh_node_log();
                }
            }
            Message::NodeLogLoaded(request_id, result) => {
                if request_id != self.node_log_request_id {
                    return Task::none();
                }
                self.node_log_loading = false;
                match result {
                    Ok(contents) => {
                        self.node_log_error = None;
                        if !self.node_log_paused
                            && self.node_log.selection().is_none()
                            && self.node_log.text() != contents
                        {
                            self.node_log = node_log_content(&contents);
                        }
                    }
                    Err(error) => {
                        self.node_log_error = Some(error);
                    }
                }
            }
            Message::ApplySettings => {
                if self.settings_applying || self.secret_action_in_flight || !self.settings_dirty()
                {
                    return Task::none();
                }
                self.settings_applying = true;
                self.settings_notice = None;
                self.settings_error = None;
                self.backend_state = BackendState::Starting;
                let backend = self.backend.clone();
                let settings = self.settings_draft();
                return Task::perform(
                    async move { backend.apply_settings(settings).await },
                    Message::SettingsApplied,
                );
            }
            Message::SettingsApplied(result) => {
                self.settings_applying = false;
                match result {
                    Ok(()) => {
                        let data_dir_changed =
                            self.settings_data_dir.trim() != self.node_settings.data_dir;
                        self.reset_settings_draft();
                        self.settings_notice = Some("Node settings applied.".into());
                        self.backend_state = BackendState::Online;
                        if data_dir_changed {
                            self.reset_wallet_views();
                            self.node_log_request_id = self.node_log_request_id.wrapping_add(1);
                            self.node_log_loading = false;
                            self.node_log = text_editor::Content::new();
                            self.node_log_error = None;
                            self.node_log_paused = false;
                            self.node_log_last_refresh = None;
                            self.matrix_b25 = MatrixCacheState::Pending;
                            self.matrix_b255 = MatrixCacheState::Pending;
                            return Task::batch([
                                self.refresh_snapshot(),
                                self.begin_matrix_preparation(),
                                self.refresh_node_log(),
                            ]);
                        }
                        return self.refresh_snapshot();
                    }
                    Err(error) => {
                        self.settings_error = Some(error);
                        self.backend_state = BackendState::Online;
                        return self.refresh_snapshot();
                    }
                }
            }
            Message::ResetSettings => {
                if !self.settings_applying && !self.secret_action_in_flight {
                    self.reset_settings_draft();
                    self.settings_notice = None;
                    self.settings_error = None;
                }
            }
            Message::BeginExportSecret => {
                if self.settings_applying || self.secret_action_in_flight || self.photo_scan_active
                {
                    return Task::none();
                }
                self.secret_dialog = Some(SecretDialog::Export);
                self.exported_master_secret.clear();
                self.imported_master_secret.clear();
                self.master_secret_copied = false;
                self.secret_action_in_flight = true;
                self.settings_notice = None;
                self.settings_error = None;
                let backend = self.backend.clone();
                return Task::perform(
                    async move { backend.export_owner_secret().await },
                    Message::ExportSecretFinished,
                );
            }
            Message::ExportSecretFinished(result) => {
                self.secret_action_in_flight = false;
                match result {
                    Ok(secret) => self.exported_master_secret = secret,
                    Err(error) => self.settings_error = Some(error),
                }
            }
            Message::CopyExportedSecret => {
                if !self.exported_master_secret.is_empty() {
                    self.master_secret_copied = true;
                    return iced::clipboard::write(self.exported_master_secret.as_str().to_owned());
                }
            }
            Message::BeginImportSecret => {
                if self.settings_applying || self.secret_action_in_flight || self.photo_scan_active
                {
                    return Task::none();
                }
                self.secret_dialog = Some(SecretDialog::Import);
                self.exported_master_secret.clear();
                self.imported_master_secret.clear();
                self.secret_import_mode = SecretImportMode::Raw;
                self.master_secret_copied = false;
                self.settings_notice = None;
                self.settings_error = None;
            }
            Message::BeginPhotoSecret => {
                if self.settings_applying || self.secret_action_in_flight || self.photo_scan_active
                {
                    return Task::none();
                }
                self.secret_dialog = Some(SecretDialog::Import);
                self.exported_master_secret.clear();
                self.imported_master_secret.clear();
                self.secret_import_mode = SecretImportMode::Photo;
                if self.secret_photo.is_some() {
                    self.photo_scan_progress = 0.0;
                    self.reset_photo_scan_timing();
                }
                self.master_secret_copied = false;
                self.settings_notice = None;
                self.settings_error = None;
            }
            Message::SetWalletSetupMode(mode) => {
                if !self.secret_action_in_flight && !self.photo_scan_active {
                    self.wallet_setup_mode = mode;
                    self.imported_master_secret.clear();
                    self.settings_error = None;
                    if mode == WalletSetupMode::Raw {
                        self.secret_import_mode = SecretImportMode::Raw;
                    } else if mode == WalletSetupMode::Photo {
                        self.secret_import_mode = SecretImportMode::Photo;
                    }
                }
            }
            Message::ChooseSecretPhoto => {
                if self.secret_action_in_flight || self.photo_scan_active {
                    return Task::none();
                }
                self.secret_action_in_flight = true;
                self.settings_notice = None;
                self.settings_error = None;
                return Task::perform(
                    async move {
                        let selected = rfd::AsyncFileDialog::new()
                            .set_title("Choose private photo")
                            .add_filter(
                                "Photos",
                                &["jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff"],
                            )
                            .pick_file()
                            .await;
                        let Some(handle) = selected else {
                            return Ok(None);
                        };
                        let path = handle.path().to_path_buf();
                        tokio::task::spawn_blocking(move || {
                            crate::secret::prepare_secret_photo(path)
                        })
                        .await
                        .map_err(|error| format!("Prepare secret photo: {error}"))?
                        .map(Box::new)
                        .map(Some)
                    },
                    Message::SecretPhotoPrepared,
                );
            }
            Message::SecretPhotoPrepared(result) => {
                self.secret_action_in_flight = false;
                match result {
                    Ok(Some(photo)) => {
                        self.secret_photo = Some(*photo);
                        self.photo_scan_progress = 0.0;
                        self.photo_scan_active = false;
                        self.photo_key_active = false;
                        self.reset_photo_scan_timing();
                        self.pending_photo_import_result = None;
                        self.settings_error = None;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        self.secret_photo = None;
                        self.photo_scan_active = false;
                        self.reset_photo_scan_timing();
                        self.pending_photo_import_result = None;
                        self.settings_error = Some(error);
                    }
                }
            }
            Message::PhotoScanTick => {
                if !self.photo_scan_active || self.secret_photo.is_none() {
                    return Task::none();
                }

                let now = Instant::now();
                if let Some(completed_at) = self.photo_scan_completed_at {
                    if now.duration_since(completed_at) >= PHOTO_SCAN_COMPLETE_HOLD {
                        self.photo_scan_active = false;
                        self.reset_photo_scan_timing();
                        let result = self
                            .pending_photo_import_result
                            .take()
                            .expect("completed photo scan has an import result");
                        return Task::done(Message::ImportSecretFinished(result));
                    }
                    return Task::none();
                }

                let elapsed = self
                    .photo_scan_last_tick
                    .replace(now)
                    .map(|last| now.saturating_duration_since(last).as_secs_f32())
                    .unwrap_or(PHOTO_SCAN_FRAME.as_secs_f32())
                    .clamp(0.001, 0.05);
                let backend_ready = self.pending_photo_import_result.is_some();
                let target_velocity =
                    if backend_ready || self.photo_scan_progress < PHOTO_SCAN_WAIT_THRESHOLD {
                        PHOTO_SCAN_SPEED
                    } else {
                        PHOTO_SCAN_CRAWL_SPEED
                    };
                let response = 1.0 - (-PHOTO_SCAN_RESPONSE * elapsed).exp();
                self.photo_scan_velocity += (target_velocity - self.photo_scan_velocity) * response;
                self.photo_scan_progress += self.photo_scan_velocity * elapsed;

                if backend_ready {
                    if self.photo_scan_progress >= 1.0 {
                        self.photo_scan_progress = 1.0;
                        self.photo_scan_velocity = 0.0;
                        self.photo_scan_completed_at = Some(now);
                    }
                } else {
                    self.photo_scan_progress = self.photo_scan_progress.min(PHOTO_SCAN_WAIT_LIMIT);
                }
            }
            Message::PhotoImportFinished(result) => {
                self.pending_photo_import_result = Some(result);
            }
            Message::ImportSecretChanged(secret) => {
                if !self.secret_action_in_flight {
                    self.imported_master_secret = secret;
                    self.settings_error = None;
                }
            }
            Message::PasteImportSecret => {
                if self.settings_applying
                    || self.secret_action_in_flight
                    || self.photo_scan_active
                    || !self.raw_secret_import_open()
                {
                    return Task::none();
                }
                return iced::clipboard::read().map(|contents| {
                    Message::ImportSecretClipboardLoaded(contents.map(|contents| {
                        SensitiveString::new(
                            contents
                                .chars()
                                .filter(|character| !character.is_ascii_whitespace())
                                .collect(),
                        )
                    }))
                });
            }
            Message::ImportSecretClipboardLoaded(secret) => {
                if self.settings_applying
                    || self.secret_action_in_flight
                    || self.photo_scan_active
                    || !self.raw_secret_import_open()
                {
                    return Task::none();
                }
                if let Some(secret) = secret {
                    self.imported_master_secret = secret;
                    self.settings_error = None;
                } else {
                    self.settings_error = Some("Clipboard does not contain text.".into());
                }
            }
            Message::ConfirmImportSecret => {
                if self.settings_applying || self.secret_action_in_flight || self.photo_scan_active
                {
                    return Task::none();
                }
                let import_mode = if self.wallet_setup_required {
                    match self.wallet_setup_mode {
                        WalletSetupMode::Raw => SecretImportMode::Raw,
                        WalletSetupMode::Photo => SecretImportMode::Photo,
                        _ => return Task::none(),
                    }
                } else {
                    self.secret_import_mode
                };
                let master_secret = match import_mode {
                    SecretImportMode::Raw if self.imported_master_secret_valid() => {
                        self.imported_master_secret.clone()
                    }
                    SecretImportMode::Raw => {
                        self.settings_error = Some(
                            "Master secret must contain exactly 64 hexadecimal characters.".into(),
                        );
                        return Task::none();
                    }
                    SecretImportMode::Photo => {
                        let Some(photo) = self.secret_photo.as_ref() else {
                            self.settings_error = Some("Choose a photo first.".into());
                            return Task::none();
                        };
                        photo.master_secret()
                    }
                };
                self.secret_action_in_flight = true;
                self.settings_notice = None;
                self.settings_error = None;
                self.backend_state = BackendState::Starting;
                let backend = self.backend.clone();
                let first_run = self.wallet_setup_required;
                if import_mode == SecretImportMode::Photo {
                    self.photo_scan_progress = 0.0;
                    self.photo_scan_active = true;
                    self.photo_scan_last_tick = Some(Instant::now());
                    self.photo_scan_velocity = 0.0;
                    self.photo_scan_completed_at = None;
                    self.pending_photo_import_result = None;
                    return Task::perform(
                        async move {
                            if first_run {
                                backend.initialize_owner_secret(master_secret).await
                            } else {
                                backend.import_owner_secret(master_secret).await
                            }
                        },
                        Message::PhotoImportFinished,
                    );
                }
                return Task::perform(
                    async move {
                        if first_run {
                            backend.initialize_owner_secret(master_secret).await
                        } else {
                            backend.import_owner_secret(master_secret).await
                        }
                    },
                    Message::ImportSecretFinished,
                );
            }
            Message::BeginGenerateSecret => {
                if self.settings_applying || self.secret_action_in_flight || self.photo_scan_active
                {
                    return Task::none();
                }
                self.secret_dialog = Some(SecretDialog::Generate);
                self.exported_master_secret.clear();
                self.imported_master_secret.clear();
                self.master_secret_copied = false;
                self.settings_notice = None;
                self.settings_error = None;
            }
            Message::ConfirmGenerateSecret => {
                if self.settings_applying || self.secret_action_in_flight {
                    return Task::none();
                }
                self.secret_action_in_flight = true;
                self.settings_notice = None;
                self.settings_error = None;
                self.backend_state = BackendState::Starting;
                let backend = self.backend.clone();
                let first_run = self.wallet_setup_required;
                return Task::perform(
                    async move {
                        if first_run {
                            backend.initialize_random_owner_secret().await
                        } else {
                            backend.generate_owner_secret().await
                        }
                    },
                    Message::ImportSecretFinished,
                );
            }
            Message::CloseSecretDialog => {
                if !self.secret_action_in_flight && !self.photo_scan_active {
                    self.secret_dialog = None;
                    self.exported_master_secret.clear();
                    self.imported_master_secret.clear();
                    self.master_secret_copied = false;
                    self.settings_error = None;
                }
            }
            Message::ImportSecretFinished(result) => {
                self.secret_action_in_flight = false;
                let first_run = self.wallet_setup_required;
                let used_photo = if first_run {
                    self.wallet_setup_mode == WalletSetupMode::Photo
                } else {
                    self.secret_dialog == Some(SecretDialog::Import)
                        && self.secret_import_mode == SecretImportMode::Photo
                };
                let discover_addresses = if first_run {
                    matches!(
                        self.wallet_setup_mode,
                        WalletSetupMode::Raw | WalletSetupMode::Photo
                    )
                } else {
                    self.secret_dialog == Some(SecretDialog::Import)
                };
                match result {
                    Ok(_) => {
                        self.secret_dialog = None;
                        self.imported_master_secret.clear();
                        self.address_discovery_pending = discover_addresses;
                        self.address_discovery_in_flight = false;
                        self.photo_key_active = used_photo;
                        if !used_photo {
                            self.secret_photo = None;
                            self.photo_scan_progress = 1.0;
                        }
                        self.photo_scan_active = false;
                        self.reset_photo_scan_timing();
                        self.pending_photo_import_result = None;
                        self.wallet_setup_required = false;
                        self.wallet_setup_mode = WalletSetupMode::Choose;
                        self.reset_wallet_views();
                        self.settings_notice = None;
                        self.backend_state = BackendState::Online;
                        return Task::batch([
                            self.refresh_snapshot(),
                            self.begin_matrix_preparation(),
                        ]);
                    }
                    Err(error) => {
                        if used_photo {
                            self.photo_scan_progress = 0.0;
                            self.photo_scan_active = false;
                            self.reset_photo_scan_timing();
                            self.pending_photo_import_result = None;
                        }
                        let installed_during_first_run =
                            first_run && !self.backend.wallet_setup_required();
                        if installed_during_first_run {
                            self.wallet_setup_required = false;
                            self.wallet_setup_mode = WalletSetupMode::Choose;
                            self.backend_state = BackendState::Offline;
                            self.backend_error = Some(error);
                        } else {
                            self.settings_error = Some(error);
                            self.backend_state = if first_run {
                                BackendState::Offline
                            } else {
                                BackendState::Online
                            };
                        }
                        if !first_run {
                            return self.refresh_snapshot();
                        }
                    }
                }
            }
            Message::PrepareMatrices => return self.begin_matrix_preparation(),
            Message::B25MatrixPrepared(preparation_id, result) => {
                if preparation_id != self.matrix_preparation_id {
                    return Task::none();
                }
                self.matrix_b25 = match result {
                    Ok(()) => MatrixCacheState::Ready,
                    Err(error) => MatrixCacheState::Failed(error),
                };
                self.matrix_b255 = MatrixCacheState::Preparing;
                let backend = self.backend.clone();
                return Task::perform(
                    async move { backend.prepare_matrix_cache(MatrixClass::B255).await },
                    move |result| Message::B255MatrixPrepared(preparation_id, result),
                );
            }
            Message::B255MatrixPrepared(preparation_id, result) => {
                if preparation_id != self.matrix_preparation_id {
                    return Task::none();
                }
                self.matrix_b255 = match result {
                    Ok(()) => MatrixCacheState::Ready,
                    Err(error) => MatrixCacheState::Failed(error),
                };
            }
            Message::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Named(key),
                repeat: false,
                ..
            }) => {
                use iced::keyboard::key::Named;
                let shortcut = if self.wallet_setup_required {
                    match key {
                        Named::F10 => Some(Message::Exit),
                        Named::Escape if self.wallet_setup_mode != WalletSetupMode::Choose => {
                            Some(Message::SetWalletSetupMode(WalletSetupMode::Choose))
                        }
                        _ => None,
                    }
                } else {
                    match key {
                        Named::F1 => Some(Message::Navigate(Section::Present)),
                        Named::F2 => Some(Message::ToggleAddressPicker),
                        Named::F3 => Some(Message::OpenAction(Action::Send)),
                        Named::F4 => Some(Message::Navigate(Section::Proofs)),
                        Named::F5 => Some(Message::Navigate(Section::Mine)),
                        Named::F6 => Some(Message::Navigate(Section::Explorer)),
                        Named::F7 => Some(Message::Navigate(Section::Settings)),
                        Named::F10 => Some(Message::Exit),
                        Named::Escape if self.block_transaction_position.is_some() => {
                            Some(Message::CloseBlockTransaction)
                        }
                        Named::Escape if self.block_details.is_some() => {
                            Some(Message::CloseBlockDetails)
                        }
                        Named::Escape if self.editing_address.is_some() => {
                            Some(Message::CancelAddressLabel)
                        }
                        Named::Escape if self.address_picker_open => {
                            Some(Message::ToggleAddressPicker)
                        }
                        Named::Escape if self.action.is_some() => Some(Message::CloseAction),
                        Named::Escape if self.explorer_result.is_some() => {
                            Some(Message::ClearExplorerSearch)
                        }
                        Named::Escape if self.secret_dialog.is_some() => {
                            Some(Message::CloseSecretDialog)
                        }
                        _ => None,
                    }
                };
                if let Some(shortcut) = shortcut {
                    return self.update(shortcut);
                }
            }
            Message::Keyboard(_) => {}
            Message::Noop => {}
            Message::Exit => {
                if self.shutting_down || self.wallet_action_in_flight() {
                    return Task::none();
                }
                self.shutting_down = true;
                self.shutdown_forge_started_at = Some(Instant::now());
                let backend = self.backend.clone();
                return Task::perform(
                    async move {
                        let _ = backend.shutdown().await;
                    },
                    |_| Message::ExitReady,
                );
            }
            Message::ShutdownForgeTick => {}
            Message::ExitReady => return iced::exit(),
        }

        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        crate::i18n::activate(self.language);
        view::root(self)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subscriptions = vec![
            iced::window::close_requests().map(|_| Message::Exit),
            iced::event::listen_with(|event, _status, _window| match event {
                iced::Event::Keyboard(event) => Some(Message::Keyboard(event)),
                iced::Event::Window(iced::window::Event::Focused) => {
                    Some(Message::WindowFocused(true))
                }
                iced::Event::Window(iced::window::Event::Unfocused) => {
                    Some(Message::WindowFocused(false))
                }
                _ => None,
            }),
        ];
        if self.refresh_timer_needed() {
            subscriptions
                .push(iced::time::every(Duration::from_secs(1)).map(|_| Message::RefreshTick));
        }
        if self.shutting_down {
            subscriptions
                .push(iced::time::every(SHUTDOWN_FORGE_FRAME).map(|_| Message::ShutdownForgeTick));
        } else if self.language_selection_required {
            subscriptions
                .push(iced::time::every(LANGUAGE_FORGE_FRAME).map(|_| Message::LanguageForgeTick));
        } else if self.photo_scan_active {
            subscriptions.push(iced::time::every(PHOTO_SCAN_FRAME).map(|_| Message::PhotoScanTick));
        } else if self.send_in_flight || self.consolidation_in_flight {
            subscriptions
                .push(iced::time::every(PROOF_FORGE_FRAME).map(|_| Message::ProofForgeTick));
        }
        if self.consolidation_hint_close_ticks > 0 {
            subscriptions.push(
                iced::time::every(CONSOLIDATION_HINT_CLOSE_FRAME)
                    .map(|_| Message::ConsolidationHintCloseTick),
            );
        }
        if self.window_focused && self.header_coin_rotating() && !self.shutting_down {
            subscriptions.push(iced::time::every(HEADER_COIN_FRAME).map(Message::HeaderCoinTick));
        }
        Subscription::batch(subscriptions)
    }

    pub fn header_coin_angle(&self) -> f32 {
        if !self.header_coin_rotating() {
            return 0.0;
        }
        (self.header_coin_elapsed.as_secs_f32() / HEADER_COIN_TURN_SECONDS * std::f32::consts::TAU)
            % std::f32::consts::TAU
    }

    fn header_coin_rotating(&self) -> bool {
        !self.language_selection_required
            && !self.wallet_setup_required
            && self.backend_state == BackendState::Online
            && !self.snapshot.network.synced
    }

    pub fn consolidation_recommended(&self) -> bool {
        self.snapshot.active_address().spendable_utxo_count() >= WALLET_CONSOLIDATION_INPUT_LIMIT
    }

    pub fn visible_utxo_count(&self) -> usize {
        self.snapshot
            .utxos
            .iter()
            .filter(|utxo| {
                self.utxo_segment_filter
                    .is_none_or(|segment| utxo.segment == segment)
            })
            .count()
    }

    pub fn utxo_page_count(&self) -> usize {
        utxo_page_count_for(self.visible_utxo_count())
    }

    pub fn proof_forge_elapsed_seconds(&self) -> f32 {
        self.proof_forge_started_at
            .map(|started_at| started_at.elapsed().as_secs_f32())
            .unwrap_or(0.0)
    }

    pub fn shutting_down(&self) -> bool {
        self.shutting_down
    }

    pub fn shutdown_forge_elapsed_seconds(&self) -> f32 {
        self.shutdown_forge_started_at
            .map(|started_at| started_at.elapsed().as_secs_f32())
            .unwrap_or(0.0)
    }

    pub fn language_forge_elapsed_seconds(&self) -> f32 {
        self.language_forge_started_at.elapsed().as_secs_f32()
    }

    pub fn wallet_action_in_flight(&self) -> bool {
        self.send_in_flight || self.consolidation_plan_in_flight || self.consolidation_in_flight
    }

    pub fn settings_dirty(&self) -> bool {
        self.settings_draft() != self.node_settings
    }

    pub fn imported_master_secret_valid(&self) -> bool {
        let mut digits = 0usize;
        for character in self.imported_master_secret.as_str().chars() {
            if character.is_ascii_whitespace() {
                continue;
            }
            if !character.is_ascii_hexdigit() {
                return false;
            }
            digits += 1;
        }
        digits == 64
    }

    fn raw_secret_import_open(&self) -> bool {
        if self.wallet_setup_required {
            self.wallet_setup_mode == WalletSetupMode::Raw
        } else {
            self.secret_dialog == Some(SecretDialog::Import)
                && self.secret_import_mode == SecretImportMode::Raw
        }
    }

    fn settings_draft(&self) -> NodeSettingsSnapshot {
        NodeSettingsSnapshot {
            data_dir: self.settings_data_dir.trim().to_owned(),
            p2p_listen: self.settings_p2p_listen.trim().to_owned(),
            custom_seeds: self
                .settings_seeds
                .text()
                .lines()
                .map(str::trim)
                .filter(|seed| !seed.is_empty())
                .map(str::to_owned)
                .collect(),
            log_level: self.settings_log_level,
        }
    }

    fn reset_settings_draft(&mut self) {
        self.node_settings = self.backend.settings_snapshot();
        self.settings_data_dir = self.node_settings.data_dir.clone();
        self.settings_p2p_listen = self.node_settings.p2p_listen.clone();
        self.settings_seeds =
            text_editor::Content::with_text(&self.node_settings.custom_seeds.join("\n"));
        self.settings_log_level = self.node_settings.log_level;
    }

    fn reset_photo_scan_timing(&mut self) {
        self.photo_scan_last_tick = None;
        self.photo_scan_velocity = 0.0;
        self.photo_scan_completed_at = None;
    }

    fn begin_matrix_preparation(&mut self) -> Task<Message> {
        if self.backend.is_mock()
            || matches!(self.matrix_b25, MatrixCacheState::Preparing)
            || (self.matrix_b25 == MatrixCacheState::Ready
                && self.matrix_b255 == MatrixCacheState::Ready)
        {
            return Task::none();
        }
        self.matrix_b25 = MatrixCacheState::Preparing;
        self.matrix_b255 = MatrixCacheState::Pending;
        self.matrix_preparation_id = self.matrix_preparation_id.wrapping_add(1);
        let preparation_id = self.matrix_preparation_id;
        let backend = self.backend.clone();
        Task::perform(
            async move { backend.prepare_matrix_cache(MatrixClass::B25).await },
            move |result| Message::B25MatrixPrepared(preparation_id, result),
        )
    }

    fn reset_wallet_views(&mut self) {
        for address in &mut self.snapshot.addresses {
            address.label = if address.key_index == 0 {
                "Main".into()
            } else {
                format!("Address {}", address.key_index)
            };
        }
        self.selected_utxo_slot = None;
        self.utxo_segment_filter = None;
        self.utxo_page = 1;
        self.copied_address = None;
        self.copied_value = None;
        self.mining_page = 1;
        self.receipt_page = 1;
        self.receipts = ReceiptsSnapshot::empty();
        self.receipts_loaded_height = None;
        self.selected_receipt_txid = None;
        self.receipt_detail = None;
        self.explorer_result = None;
        self.explorer_query.clear();
        self.block_details = None;
        self.block_transaction_position = None;
    }

    fn close_consolidation_hint(&mut self) {
        self.consolidation_hint_open = false;
        self.consolidation_badge_hovered = false;
        self.consolidation_card_hovered = false;
        self.consolidation_hint_close_ticks = 0;
    }

    fn node_log_visible(&self) -> bool {
        !self.wallet_setup_required
            && self.section == Section::Settings
            && self.settings_tab == SettingsTab::Node
    }

    fn snapshot_refresh_available(&self) -> bool {
        !self.backend.is_mock()
            && !self.wallet_setup_required
            && !self.refresh_in_flight
            && !self.ensure_in_flight
            && !self.node_action_in_flight
            && !self.wallet_action_in_flight()
            && self.address_operation.is_none()
            && !self.shutting_down
    }

    fn refresh_timer_needed(&self) -> bool {
        self.snapshot_refresh_available()
            || (!self.backend.is_mock()
                && self.node_log_visible()
                && !self.node_log_loading
                && !self.shutting_down)
    }

    fn resume_node_log(&mut self) {
        self.node_log = node_log_content(&self.node_log.text());
        self.node_log_paused = false;
        self.node_log_last_refresh = None;
    }

    fn node_log_refresh_due(&self) -> bool {
        self.node_log_visible()
            && !self.node_log_loading
            && !self.node_log_paused
            && self.node_log.selection().is_none()
            && self
                .node_log_last_refresh
                .is_none_or(|refreshed| refreshed.elapsed() >= NODE_LOG_REFRESH_INTERVAL)
    }

    fn refresh_node_log(&mut self) -> Task<Message> {
        if !self.node_log_visible() || self.node_log_loading {
            return Task::none();
        }
        self.node_log_loading = true;
        self.node_log_last_refresh = Some(Instant::now());
        self.node_log_request_id = self.node_log_request_id.wrapping_add(1);
        let request_id = self.node_log_request_id;
        let backend = self.backend.clone();
        Task::perform(
            async move {
                backend
                    .node_log_tail(NODE_LOG_BYTE_LIMIT, NODE_LOG_LINE_LIMIT)
                    .await
            },
            move |result| Message::NodeLogLoaded(request_id, result),
        )
    }

    fn refresh_snapshot(&mut self) -> Task<Message> {
        if self.refresh_in_flight {
            return Task::none();
        }
        self.refresh_in_flight = true;
        let backend = self.backend.clone();
        let mining_page = self.mining_page;
        Task::perform(
            async move { backend.snapshot(mining_page).await.map(Box::new) },
            Message::SnapshotLoaded,
        )
    }

    fn refresh_receipts_view(&mut self) -> Task<Message> {
        if self.receipts_loading {
            return Task::none();
        }
        self.receipts_loading = true;
        self.receipt_error = None;
        let backend = self.backend.clone();
        let page = self.receipt_page;
        Task::perform(
            async move { backend.receipts_snapshot(page).await.map(Box::new) },
            Message::ReceiptsLoaded,
        )
    }

    fn load_receipt_detail(&mut self, txid: String) -> Task<Message> {
        if self.receipt_detail_loading {
            return Task::none();
        }
        self.receipt_detail_loading = true;
        self.receipt_error = None;
        let backend = self.backend.clone();
        let requested_txid = txid.clone();
        Task::perform(
            async move { backend.receipt_detail(requested_txid).await.map(Box::new) },
            move |result| Message::ReceiptDetailLoaded(txid, result),
        )
    }

    fn load_explorer(&mut self) -> Task<Message> {
        if self.explorer_loading {
            return Task::none();
        }
        self.explorer_loading = true;
        self.explorer_error = None;
        let backend = self.backend.clone();
        let block_page = self.explorer_block_page;
        let transaction_page = self.explorer_transaction_page;
        Task::perform(
            async move {
                backend
                    .explorer_snapshot(block_page, transaction_page)
                    .await
                    .map(Box::new)
            },
            Message::ExplorerLoaded,
        )
    }

    fn refresh_explorer_view(&mut self) -> Task<Message> {
        let explorer = self.load_explorer();
        if matches!(
            self.explorer_result,
            Some(ExplorerSearchResultSnapshot::Address(_))
        ) {
            Task::batch([explorer, self.search_explorer()])
        } else {
            explorer
        }
    }

    fn search_explorer(&mut self) -> Task<Message> {
        if self.explorer_searching {
            return Task::none();
        }
        let query = self.explorer_query.trim().to_owned();
        if query.is_empty() {
            self.explorer_error = Some("Enter an address, block, transaction, or slot.".into());
            return Task::none();
        }
        self.explorer_searching = true;
        self.explorer_search_id = self.explorer_search_id.wrapping_add(1);
        let search_id = self.explorer_search_id;
        self.explorer_error = None;
        let backend = self.backend.clone();
        let transaction_page = self.explorer_transaction_page;
        Task::perform(
            async move {
                backend
                    .explorer_search(query, transaction_page)
                    .await
                    .map(Box::new)
            },
            move |result| Message::ExplorerSearchLoaded(search_id, result),
        )
    }
}

fn parse_noid_amount(input: &str) -> Result<u64, String> {
    let normalized = input.trim().replace(',', ".");
    if normalized.is_empty() {
        return Err("Enter an amount.".into());
    }
    if normalized.starts_with('-') || normalized.starts_with('+') {
        return Err("Amount must be a positive NOID value.".into());
    }
    let mut parts = normalized.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("Use a decimal NOID amount, for example 12.500000.".into());
    }
    if fractional.len() > 6 {
        return Err("NOID supports at most 6 decimal places.".into());
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|_| "Amount is too large.".to_string())?;
    let fractional = if fractional.is_empty() {
        0
    } else {
        let digits = fractional
            .parse::<u64>()
            .map_err(|_| "Invalid fractional amount.".to_string())?;
        digits
            .checked_mul(10u64.pow((6 - fractional.len()) as u32))
            .ok_or_else(|| "Amount is too large.".to_string())?
    };
    let amount = whole
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(fractional))
        .ok_or_else(|| "Amount is too large.".to_string())?;
    if amount == 0 {
        return Err("Amount must be at least 0.000001 NOID.".into());
    }
    Ok(amount)
}

fn parse_optional_noid_fee(input: &str) -> Result<u64, String> {
    if input.trim().is_empty() {
        return Ok(0);
    }
    parse_noid_amount(input).map_err(|error| format!("Invalid network fee: {error}"))
}

fn utxo_page_count_for(output_count: usize) -> usize {
    output_count.div_ceil(UTXO_PAGE_SIZE).max(1)
}

fn normalize_utxo_page_after_refresh(
    current_page: usize,
    page_count: usize,
    filter_removed: bool,
) -> usize {
    if filter_removed {
        1
    } else {
        current_page.min(page_count.max(1))
    }
}

fn record_snapshot_refresh_failure(
    _backend_state: &mut BackendState,
    consecutive_failures: &mut u8,
) -> bool {
    *consecutive_failures = consecutive_failures.saturating_add(1);
    if *consecutive_failures < 3 {
        return false;
    }
    // A busy snapshot commit can temporarily hold the node's atomic storage
    // writer long enough for GUI RPC refreshes to time out. That is not proof
    // that the process is offline, so preserve the last known state while the
    // supervisor performs the actual liveness check.
    true
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_utxo_page_after_refresh, parse_noid_amount, parse_optional_noid_fee,
        record_snapshot_refresh_failure, utxo_page_count_for, BackendState,
    };

    #[test]
    fn parses_noid_without_floating_point() {
        assert_eq!(parse_noid_amount("1").unwrap(), 1_000_000);
        assert_eq!(parse_noid_amount("0.000001").unwrap(), 1);
        assert_eq!(parse_noid_amount("12,5").unwrap(), 12_500_000);
        assert!(parse_noid_amount("0").is_err());
        assert!(parse_noid_amount("1.0000001").is_err());
        assert!(parse_noid_amount("1.2.3").is_err());
    }

    #[test]
    fn parses_blank_fee_as_automatic_and_explicit_fee_exactly() {
        assert_eq!(parse_optional_noid_fee("").unwrap(), 0);
        assert_eq!(parse_optional_noid_fee("   ").unwrap(), 0);
        assert_eq!(parse_optional_noid_fee("0.01").unwrap(), 10_000);
        assert!(parse_optional_noid_fee("0").is_err());
        assert!(parse_optional_noid_fee("fee").is_err());
    }

    #[test]
    fn utxo_pagination_handles_empty_boundaries_and_thousands() {
        assert_eq!(utxo_page_count_for(0), 1);
        assert_eq!(utxo_page_count_for(25), 1);
        assert_eq!(utxo_page_count_for(26), 2);
        assert_eq!(utxo_page_count_for(10_000), 400);
    }

    #[test]
    fn utxo_refresh_preserves_the_current_page_without_a_segment_filter() {
        assert_eq!(normalize_utxo_page_after_refresh(2, 4, false), 2);
        assert_eq!(normalize_utxo_page_after_refresh(4, 2, false), 2);
        assert_eq!(normalize_utxo_page_after_refresh(2, 4, true), 1);
    }

    #[test]
    fn transient_snapshot_rpc_timeouts_never_claim_the_node_is_offline() {
        let mut state = BackendState::Online;
        let mut failures = 0;
        assert!(!record_snapshot_refresh_failure(&mut state, &mut failures));
        assert_eq!(state, BackendState::Online);
        assert!(!record_snapshot_refresh_failure(&mut state, &mut failures));
        assert_eq!(state, BackendState::Online);
        assert!(record_snapshot_refresh_failure(&mut state, &mut failures));
        assert_eq!(state, BackendState::Online);
        assert_ne!(state, BackendState::Offline);
    }
}
