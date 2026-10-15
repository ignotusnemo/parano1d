// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Presentation state for contracts. The daemon constructs policies, checks
//! live incarnations, authorizes calls and verifies receipts through RPC.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

mod workflow;
pub use workflow::*;

pub const TERMS_LIMIT: usize = 32 * 1024;
pub const LIBRARY_LIMIT: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    pub source: String,
    pub inverted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramStep {
    pub opcode: String,
    pub destination: String,
    pub left: String,
    pub right: String,
    pub predicate: Predicate,
    pub immediate: String,
}

const REGISTERS: &[&str] = &["state0", "state1", "scratch0", "scratch1"];
const OPERANDS: &[&str] = &[
    "state0",
    "state1",
    "scratch0",
    "scratch1",
    "immediate",
    "height",
    "fee",
    "payout",
    "retained",
    "input_amount",
    "before_deadline",
    "terminal",
    "has_payout",
    "zero",
    "one",
    "after_deadline",
    "payout_owner0",
    "payout_owner1",
    "payout_owner2",
    "payout_owner3",
    "input_creation_id",
    "input_slot",
    "retained_slot",
    "payout_slot",
];

fn integer(value: &str) -> bool {
    !(value.is_empty() || value.len() > 1 && value.starts_with('0'))
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

impl ProgramStep {
    fn valid(&self) -> bool {
        [
            "keep",
            "move",
            "add",
            "subtract",
            "min",
            "max",
            "less_than",
            "equal",
            "assert_equal",
            "assert_less_or_equal",
        ]
        .contains(&self.opcode.as_str())
            && REGISTERS.contains(&self.destination.as_str())
            && OPERANDS.contains(&self.left.as_str())
            && OPERANDS.contains(&self.right.as_str())
            && [
                "always",
                "before_deadline",
                "terminal",
                "has_payout",
                "scratch0",
                "scratch1",
            ]
            .contains(&self.predicate.source.as_str())
            && integer(&self.immediate)
    }

    pub fn formula(&self, _step: usize) -> String {
        let operand = |name: &str| {
            if name == "immediate" {
                self.immediate.clone()
            } else {
                name.to_owned()
            }
        };
        let left = operand(&self.left);
        let right = operand(&self.right);
        let rhs = match self.opcode.as_str() {
            "keep" => "keep".into(),
            "move" => format!("{} = {left}", self.destination),
            "add" => format!("{} = {left} + {right}", self.destination),
            "subtract" => format!("{} = {left} - {right}", self.destination),
            "less_than" => format!("{} = ({left} < {right})", self.destination),
            "equal" => format!("{} = ({left} == {right})", self.destination),
            "assert_equal" => format!("assert {left} == {right}"),
            "assert_less_or_equal" => format!("assert {left} <= {right}"),
            "min" | "max" => format!("{} = {}({left}, {right})", self.destination, self.opcode),
            _ => "unsupported instruction".into(),
        };
        if self.predicate.source == "always" && !self.predicate.inverted {
            rhs
        } else {
            format!(
                "if {}{}: {rhs}",
                if self.predicate.inverted { "!" } else { "" },
                self.predicate.source
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub abi_version: u16,
    pub state: [String; 2],
    pub address: String,
    pub opening_hex: String,
    pub code_id: String,
    pub state_hex: String,
    pub program: Vec<ProgramStep>,
    pub claim_authority: String,
    pub recovery_authority: String,
    pub claim_recipient: String,
    pub recovery_recipient: String,
    pub deadline_height: u64,
    pub max_fee_micronoid: u64,
    pub max_payout_micronoid: u64,
    pub min_retained_micronoid: u64,
    pub claim_can_continue: bool,
    pub claim_can_close: bool,
    pub recovery_can_continue: bool,
    pub recovery_can_close: bool,
    pub unrestricted_payout_recipient: bool,
}

impl Info {
    /// Local grouping only; authorization always uses the full opening.
    pub fn family_key(&self) -> String {
        let mut definition = self.editable_definition();
        definition["definition"]
            .as_object_mut()
            .unwrap()
            .remove("state");
        blake3::hash(&serde_json::to_vec(&definition).unwrap())
            .to_hex()
            .to_string()
    }

    pub fn has_program_details(&self) -> bool {
        let field = |value: &str, digits| {
            value.len() == digits && value.bytes().all(|b| b.is_ascii_hexdigit())
        };
        self.abi_version == 3
            && self.program.len() == 16
            && self.state.iter().all(|s| integer(s))
            && field(&self.code_id, 64)
            && field(&self.state_hex, 32)
            && self.program.iter().all(ProgramStep::valid)
    }

    pub fn policy_only(&self) -> bool {
        self.has_program_details() && self.program.iter().all(|step| step.opcode == "keep")
    }

    pub fn editable_definition(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("serializable terms");
        let fields = value.as_object_mut().unwrap();
        for name in [
            "abi_version",
            "address",
            "opening_hex",
            "code_id",
            "state_hex",
        ] {
            fields.remove(name);
        }
        json!({"kind":"custom_program", "definition":value})
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Protocol {
    pub activation_height: Option<u64>,
    pub runtime_available: bool,
    pub abi_version: u16,
}

impl Protocol {
    pub fn available(&self, height: u64) -> bool {
        self.runtime_available
            && self.abi_version == 3
            && self
                .activation_height
                .is_some_and(|h| height.checked_add(1).is_some_and(|next| next >= h))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryEntry {
    pub name: String,
    pub info: Info,
    /// A signed call can miss its inclusion height. Keep the preceding terms
    /// alongside its candidate instead of silently replacing a live contract.
    #[serde(default)]
    pub candidate: Option<Info>,
    #[serde(default)]
    pub kind: Option<Kind>,
    #[serde(default)]
    pub source: Source,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KnownState {
    pub object: Info,
    pub has_balance: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KnownStates {
    pub states: Vec<KnownState>,
    pub height: u64,
    pub next_root: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Payout {
    pub address: String,
    pub amount_micronoid: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Preview {
    pub txid: String,
    pub call_height: u64,
    pub authority: String,
    pub recovery: bool,
    pub terminal: bool,
    pub fee_micronoid: u64,
    pub retained_micronoid: u64,
    pub payout: Option<Payout>,
    pub successor: Option<Info>,
}

impl Preview {
    pub fn bind(&self, payload: &mut Value) -> Result<(), String> {
        if self.txid.len() != 64
            || !self.txid.bytes().all(|b| b.is_ascii_hexdigit())
            || payload["expected_authority"] != self.authority
            || payload["terminal"] != self.terminal
            || payload["expected_recovery"] != self.recovery
        {
            return Err("The preview does not match the requested call.".into());
        }
        if !self.terminal {
            let matches = match (&self.payout, payload.get("payout")) {
                (None, Some(Value::Null)) => true,
                (Some(payout), Some(value)) => {
                    value["address"] == payout.address
                        && value["amount_micronoid"] == payout.amount_micronoid
                }
                _ => false,
            };
            if !matches {
                return Err("The preview does not match the requested call.".into());
            }
        }
        payload["expected_txid"] = json!(self.txid);
        payload["expected_call_height"] = json!(self.call_height);
        payload["fee_micronoid"] = json!(self.fee_micronoid);
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Instance {
    pub slot_index: u32,
    pub value: u64,
    pub creation_id: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Instances {
    pub height: u64,
    pub slots: Vec<Instance>,
    pub next_slot: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Payment,
    Vault,
    Allowance,
    Budget,
    Recurring,
    Vesting,
    Custom,
}

impl Kind {
    pub const ALL: [Self; 7] = [
        Self::Payment,
        Self::Vault,
        Self::Allowance,
        Self::Budget,
        Self::Recurring,
        Self::Vesting,
        Self::Custom,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Payment => "PAYMENT WITH REFUND",
            Self::Vault => "TIMELOCKED VAULT",
            Self::Allowance => "ALLOWANCE WALLET",
            Self::Budget => "PERIOD BUDGET",
            Self::Recurring => "RECURRING PAYMENT",
            Self::Vesting => "GRADUAL UNLOCK",
            Self::Custom => "CUSTOM PROGRAM",
        }
    }
}
impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::translate(self.label()))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Field {
    DraftName,
    InitialAmount,
    InitialFee,
    FilePath,
    Payout,
    Authority,
    Deadline,
    MaxFee,
    MaxPayment,
    Reserve,
    Payee,
    Amount,
    Fee,
    Start,
    Period,
    Budget,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Create,
    Mine,
    Open,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifiedReceipt {
    pub txid: String,
    pub height: u64,
    pub terminal: bool,
    pub authority: String,
    pub original: Info,
    pub successor: Option<Info>,
    pub input_micronoid: u64,
    pub fee_micronoid: u64,
    pub retained_micronoid: u64,
    pub payout: Option<Payout>,
}

#[derive(Debug, Clone)]
pub enum Action {
    Use(UseAction),
    ShowHelp(Kind),
    CloseHelp,
    CreateAndFund,
    BrowseFile,
    OpenFile,
    AcceptFile,
    Poll,
    SelectOperation(usize),
    SaveOperationReceipt(usize),
    SetDetail(DetailTab),
    SetTab(Tab),
    ToggleProgram,
    Home,
    LoadSaved(usize),
    Rename,
    Forget(usize),
    EditProgram(iced::widget::text_editor::Action),
    EditLoaded,
    UseCandidate,
    UseKnownState(usize),
    NextStates,
    ReviewContinue,
    Kind(Kind),
    Edit(Field, String),
    Select(u32),
    Create,
    Refresh,
    NextPage,
    Save,
    ReviewFund,
    ReviewClose,
    ReviewPay,
    Confirm,
    CancelReview,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Request {
    OpenFile(Option<String>),
    AcceptFile(OpenedFile),
    Poll(Info),
    SaveOperationReceipt(Info, Operation),
    PrepareFunding {
        info: Info,
        amount: u64,
        fee: u64,
        sender: String,
        creation: Option<Creation>,
    },
    CreateAndFund {
        definition: Value,
        creation: Creation,
        amount: u64,
        fee: u64,
        sender: String,
    },
    SaveDraft {
        definition: Value,
        creation: Creation,
    },
    Home,
    LoadSaved(usize),
    Rename(Info, String),
    Forget(usize),
    Preview {
        info: Info,
        payload: Value,
    },
    Refresh(Info, u32),
    Related(Info, String),
    Save(Info),
    Fund {
        info: Info,
        amount: u64,
        fee: u64,
        sender: String,
        creation: Option<Creation>,
    },
    Call {
        info: Info,
        payload: Value,
        authority: String,
        recovery: bool,
        preview: Preview,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Outcome {
    FundingReview {
        info: Info,
        amount: u64,
        fee: u64,
        sender: String,
        creation: Option<Creation>,
    },
    Opened(OpenedFile),
    WithActivity(Box<Outcome>, Vec<Operation>),
    Refreshed(Box<Outcome>),
    WithNotice(Box<Outcome>, String),
    Home(Protocol, Vec<LibraryEntry>),
    Library(Vec<LibraryEntry>),
    Previewed {
        info: Info,
        payload: Value,
        preview: Preview,
    },
    Loaded(Info, Instances, Vec<LibraryEntry>, KnownStates),
    Related(KnownStates),
    Submitted {
        txid: String,
        old_opening: Option<String>,
        successor: Option<Info>,
    },
    Notice(String),
}

impl Outcome {
    pub fn reveals_content(&self) -> bool {
        match self {
            Self::Loaded(..)
            | Self::Opened(_)
            | Self::FundingReview { .. }
            | Self::Previewed { .. } => true,
            Self::WithActivity(outcome, _) | Self::WithNotice(outcome, _) => {
                outcome.reveals_content()
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct State {
    pub use_action: UseAction,
    pub help: Option<Kind>,
    pub detail: DetailTab,
    pub draft_name: String,
    pub initial_amount: String,
    pub initial_fee: String,
    pub file_path: String,
    pub opened: Option<OpenedFile>,
    pub operations: Vec<Operation>,
    pub selected_operation: Option<usize>,
    pub payout: String,
    pub last_poll: Option<(u64, String)>,
    pub tab: Tab,
    pub program_expanded: bool,
    pub protocol: Option<Protocol>,
    pub library: Vec<LibraryEntry>,
    pub name: String,
    pub start: String,
    pub period: String,
    pub budget: String,
    pub editor: iced::widget::text_editor::Content,
    pub candidate: Option<Info>,
    pub known_states: Option<KnownStates>,
    pub kind: Kind,
    pub authority: String,
    pub deadline: String,
    pub max_fee: String,
    pub max_payment: String,
    pub reserve: String,
    pub payee: String,
    pub amount: String,
    pub fee: String,
    pub info: Option<Info>,
    pub instances: Option<Instances>,
    pub selected: Option<u32>,
    pub busy: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub review: Option<(Request, String)>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            use_action: UseAction::Fund,
            help: None,
            detail: DetailTab::Actions,
            draft_name: String::new(),
            initial_amount: String::new(),
            initial_fee: String::new(),
            file_path: String::new(),
            opened: None,
            operations: Vec::new(),
            selected_operation: None,
            payout: String::new(),
            last_poll: None,
            tab: Tab::Create,
            program_expanded: false,
            protocol: None,
            library: Vec::new(),
            name: String::new(),
            start: String::new(),
            period: "2880".into(),
            budget: "10".into(),
            editor: iced::widget::text_editor::Content::new(),
            candidate: None,
            known_states: None,
            kind: Kind::Payment,
            authority: String::new(),
            deadline: String::new(),
            max_fee: "1".into(),
            max_payment: "3".into(),
            reserve: "2".into(),
            payee: String::new(),
            amount: String::new(),
            fee: String::new(),
            info: None,
            instances: None,
            selected: None,
            busy: false,
            error: None,
            notice: None,
            review: None,
        }
    }
}

impl State {
    pub fn selected_instance(&self) -> Option<&Instance> {
        self.instances
            .as_ref()?
            .slots
            .iter()
            .find(|slot| Some(slot.slot_index) == self.selected)
    }

    pub fn action(
        &mut self,
        action: Action,
        active: &str,
        height: u64,
    ) -> Result<Option<Request>, String> {
        // Navigation and help never authorize or mutate a contract.
        match action {
            Action::SetTab(tab) => {
                self.tab = tab;
                self.help = None;
                self.notice = None;
                self.error = None;
                return Ok(None);
            }
            Action::ShowHelp(kind) => {
                self.help = Some(kind);
                return Ok(None);
            }
            Action::CloseHelp => {
                self.help = None;
                return Ok(None);
            }
            Action::SetDetail(tab) => {
                self.detail = tab;
                return Ok(None);
            }
            _ => {}
        }
        if self.busy {
            return Ok(None);
        }
        self.error = None;
        match action {
            Action::SetTab(_) | Action::ShowHelp(_) | Action::CloseHelp | Action::SetDetail(_) => {
                unreachable!()
            }
            Action::Use(action) => {
                self.use_action = action;
                self.review = None;
            }
            Action::BrowseFile | Action::OpenFile => {
                self.opened = None;
                self.notice = None;
                return Ok(Some(Request::OpenFile(
                    if matches!(action, Action::OpenFile) {
                        if self.file_path.trim().is_empty() {
                            return Err("Choose a contract file first.".into());
                        }
                        Some(self.file_path.trim().to_owned())
                    } else {
                        None
                    },
                )));
            }
            Action::AcceptFile => {
                let file = self
                    .opened
                    .clone()
                    .ok_or("Open and check a contract file first.")?;
                if file.info.is_none() {
                    return Err("This receipt records a closed balance.".into());
                }
                return Ok(Some(Request::AcceptFile(file)));
            }
            Action::Poll => {
                if let Some(info) = &self.info {
                    return Ok(Some(Request::Poll(info.clone())));
                }
            }
            Action::SelectOperation(index) => {
                if index >= self.operations.len() {
                    return Err("Operation list changed. Refresh it.".into());
                }
                self.selected_operation = Some(index);
            }
            Action::SaveOperationReceipt(index) => {
                let op = self
                    .operations
                    .get(index)
                    .ok_or("Operation list changed. Refresh it.")?
                    .clone();
                let info = self.info.clone().ok_or("Choose a contract first.")?;
                return Ok(Some(Request::SaveOperationReceipt(info, op)));
            }
            Action::ToggleProgram => self.program_expanded = !self.program_expanded,
            Action::Home => return Ok(Some(Request::Home)),
            Action::LoadSaved(index) => {
                self.tab = Tab::Mine;
                self.detail = DetailTab::Actions;
                self.review = None;
                return Ok(Some(Request::LoadSaved(index)));
            }
            Action::Forget(index) => return Ok(Some(Request::Forget(index))),
            Action::Rename => {
                return Ok(Some(Request::Rename(
                    self.info
                        .clone()
                        .ok_or("Create or import contract terms first.")?,
                    self.name.trim().to_owned(),
                )))
            }
            Action::UseCandidate => {
                return Ok(Some(Request::Refresh(
                    self.candidate.clone().ok_or("No candidate successor.")?,
                    0,
                )))
            }
            Action::UseKnownState(index) => {
                self.review = None;
                let info = self
                    .known_states
                    .as_ref()
                    .and_then(|page| page.states.get(index))
                    .ok_or("Saved contract list changed. Reload it.")?
                    .object
                    .clone();
                return Ok(Some(Request::Refresh(info, 0)));
            }
            Action::NextStates => {
                return Ok(Some(Request::Related(
                    self.info
                        .clone()
                        .ok_or("Create or import contract terms first.")?,
                    self.known_states
                        .as_ref()
                        .and_then(|page| page.next_root.clone())
                        .ok_or("No more saved states.")?,
                )));
            }
            Action::EditProgram(action) => {
                let mut candidate =
                    iced::widget::text_editor::Content::with_text(&self.editor.text());
                // Preserve selection/cursor when editing; the bound is checked
                // after an action, including paste, before parsing or sending.
                std::mem::swap(&mut candidate, &mut self.editor);
                candidate.perform(action);
                if candidate.text().len() > TERMS_LIMIT {
                    return Err("Program exceeds its editor limit.".into());
                }
                self.editor = candidate;
                self.review = None;
            }
            Action::EditLoaded => {
                let info = self
                    .info
                    .as_ref()
                    .ok_or("Create or import contract terms first.")?;
                self.editor = iced::widget::text_editor::Content::with_text(
                    &serde_json::to_string_pretty(&info.editable_definition())
                        .map_err(|e| e.to_string())?,
                );
                self.kind = Kind::Custom;
                self.tab = Tab::Create;
                self.review = None;
            }
            Action::Edit(field, value) => {
                if value.len()
                    > if matches!(field, Field::FilePath) {
                        4096
                    } else {
                        256
                    }
                {
                    return Err("Field is too long.".into());
                }
                self.review = None;
                if matches!(field, Field::FilePath) {
                    self.opened = None;
                }
                *match field {
                    Field::DraftName => &mut self.draft_name,
                    Field::InitialAmount => &mut self.initial_amount,
                    Field::InitialFee => &mut self.initial_fee,
                    Field::FilePath => &mut self.file_path,
                    Field::Payout => &mut self.payout,
                    Field::Authority => &mut self.authority,
                    Field::Deadline => &mut self.deadline,
                    Field::MaxFee => &mut self.max_fee,
                    Field::MaxPayment => &mut self.max_payment,
                    Field::Reserve => &mut self.reserve,
                    Field::Payee => &mut self.payee,
                    Field::Amount => &mut self.amount,
                    Field::Fee => &mut self.fee,
                    Field::Start => &mut self.start,
                    Field::Period => &mut self.period,
                    Field::Budget => &mut self.budget,
                    Field::Name => &mut self.name,
                } = value;
            }
            Action::Kind(kind) => {
                if kind == Kind::Custom && self.editor.text().trim().is_empty() {
                    self.editor = iced::widget::text_editor::Content::with_text(&custom_example(
                        active, height,
                    ));
                }
                self.kind = kind;
                self.review = None;
            }
            Action::Select(slot) => {
                self.selected = Some(slot);
                self.review = None;
            }
            Action::CancelReview => self.review = None,
            Action::Confirm => {
                self.require_active(height)?;
                let Some((request, _)) = self.review.take() else {
                    return Ok(None);
                };
                match &request {
                    Request::Fund { sender, .. } if sender != active => return Err("Active address changed. Review the transaction again.".into()),
                    Request::Call { info, authority, recovery, preview, .. }
                        if authority != active || *recovery != (height.saturating_add(1) >= info.deadline_height)
                            || preview.call_height != height.saturating_add(1) =>
                        return Err("Contract authority or deadline branch changed. Review the transaction again.".into()),
                    _ => {}
                }
                if let Request::Fund { info, .. } = &request {
                    self.info = Some(info.clone());
                    self.instances = None;
                    self.selected = None;
                }
                self.tab = Tab::Mine;
                self.detail = DetailTab::Actions;
                self.last_poll = None;
                return Ok(Some(request));
            }
            Action::Create | Action::CreateAndFund => {
                self.review = None;
                let definition = self.definition(active, height)?;
                let creation = Creation {
                    name: self.draft_name.trim().to_owned(),
                    kind: self.kind,
                };
                validate_name(&creation.name)?;
                if matches!(action, Action::CreateAndFund) {
                    self.require_active(height)?;
                    return Ok(Some(Request::CreateAndFund {
                        definition,
                        creation,
                        amount: crate::app::parse_noid_amount(&self.initial_amount)?,
                        fee: crate::app::parse_optional_noid_fee(&self.initial_fee)?,
                        sender: active.to_owned(),
                    }));
                }
                return Ok(Some(Request::SaveDraft {
                    definition,
                    creation,
                }));
            }
            Action::Refresh | Action::NextPage | Action::Save => {
                let info = self
                    .info
                    .clone()
                    .ok_or("Create or import contract terms first.")?;
                let request = match action {
                    Action::Save => Request::Save(info),
                    Action::NextPage => Request::Refresh(
                        info,
                        self.instances
                            .as_ref()
                            .and_then(|v| v.next_slot)
                            .ok_or("No next page.")?,
                    ),
                    _ => Request::Refresh(info, 0),
                };
                return Ok(Some(request));
            }
            Action::ReviewFund => {
                self.require_active(height)?;
                let info = self
                    .info
                    .clone()
                    .ok_or("Create or import contract terms first.")?;
                if !info.has_program_details() {
                    return Err("The node did not provide the contract program. Update the node and reload the terms before funding.".into());
                }
                let amount = crate::app::parse_noid_amount(&self.amount)?;
                let fee = crate::app::parse_optional_noid_fee(&self.fee)?;
                return Ok(Some(Request::PrepareFunding {
                    info,
                    amount,
                    fee,
                    sender: active.to_owned(),
                    creation: None,
                }));
            }
            Action::ReviewClose | Action::ReviewPay | Action::ReviewContinue => {
                self.require_active(height)?;
                self.review = None;
                let info = self
                    .info
                    .clone()
                    .ok_or("Create or import contract terms first.")?;
                let slot = self
                    .selected_instance()
                    .ok_or("Select a funded contract first.")?;
                let closing = matches!(action, Action::ReviewClose);
                let recovery = height.saturating_add(1) >= info.deadline_height;
                let (authority, recipient, allowed) = match (recovery, closing) {
                    (false, true) => (
                        &info.claim_authority,
                        &info.claim_recipient,
                        info.claim_can_close,
                    ),
                    (true, true) => (
                        &info.recovery_authority,
                        &info.recovery_recipient,
                        info.recovery_can_close,
                    ),
                    (false, false) => (
                        &info.claim_authority,
                        &info.claim_recipient,
                        info.claim_can_continue,
                    ),
                    (true, false) => (
                        &info.recovery_authority,
                        &info.recovery_recipient,
                        info.recovery_can_continue,
                    ),
                };
                if authority != active || !allowed {
                    return Err(
                        "This action is unavailable to the active address at the next block."
                            .into(),
                    );
                }
                let fee = crate::app::parse_optional_noid_fee(&self.fee)?;
                if fee > info.max_fee_micronoid {
                    return Err("Fee exceeds the contract limit.".into());
                }
                let payout = if closing || matches!(action, Action::ReviewContinue) {
                    None
                } else {
                    let amount = crate::app::parse_noid_amount(&self.amount)?;
                    if amount > info.max_payout_micronoid {
                        return Err("Payment exceeds the per-call limit.".into());
                    }
                    let payee = if info.unrestricted_payout_recipient {
                        self.payout.trim()
                    } else {
                        recipient.as_str()
                    };
                    if payee.is_empty() {
                        return Err("Enter a payment recipient.".into());
                    }
                    Some(json!({"address":payee, "amount_micronoid":amount}))
                };
                let payload = json!({"opening_hex":info.opening_hex, "slot_index":slot.slot_index,
                    "creation_id":slot.creation_id, "terminal":closing, "payout":payout, "fee_micronoid":fee,
                    "expected_recovery":recovery, "expected_authority":active});
                return Ok(Some(Request::Preview { info, payload }));
            }
        }
        Ok(None)
    }

    fn definition(&self, active: &str, height: u64) -> Result<Value, String> {
        if self.kind == Kind::Custom {
            let definition: Value =
                serde_json::from_str(&self.editor.text()).map_err(|e| e.to_string())?;
            if definition["kind"] != "custom_program" {
                return Err("Use a custom_program definition in the editor.".into());
            }
            return Ok(definition);
        }
        let deadline = self
            .deadline
            .trim()
            .parse::<u64>()
            .map_err(|_| "Enter a block height.")?;
        if deadline <= height.saturating_add(1) {
            return Err("Choose a future block height.".into());
        }
        let max_fee = crate::app::parse_noid_amount(&self.max_fee)?;
        let number = |text: &str| {
            text.trim()
                .parse::<u64>()
                .map_err(|_| "Enter a block height or positive period.")
        };
        let start = if matches!(self.kind, Kind::Budget | Kind::Recurring | Kind::Vesting) {
            number(&self.start)?
        } else {
            0
        };
        let period = if matches!(self.kind, Kind::Budget | Kind::Recurring | Kind::Vesting) {
            number(&self.period)?
        } else {
            0
        };
        let definition = match self.kind {
            Kind::Payment => json!({"kind":"refundable_payment", "payer":active,
                        "payee":self.authority.trim(), "expiry_height":deadline, "max_fee_micronoid":max_fee}),
            Kind::Vault => json!({"kind":"timelocked_vault", "owner":active,
                        "unlock_height":deadline, "max_fee_micronoid":max_fee}),
            Kind::Allowance => json!({"kind":"allowance_wallet", "recovery_key":active,
                        "spending_key":self.authority.trim(), "recover_at":deadline,
                        "payout_recipient":(!self.payee.trim().is_empty()).then(|| self.payee.trim()),
                        "max_fee_micronoid":max_fee,
                        "max_payout_micronoid":crate::app::parse_noid_amount(&self.max_payment)?,
                        "min_retained_micronoid":if self.reserve.trim() == "0" { 0 } else { crate::app::parse_noid_amount(&self.reserve)? }}),
            Kind::Budget => {
                json!({"kind":"period_budget_wallet", "spending_key":self.authority.trim(),
                        "recovery_key":active, "payout_recipient":(!self.payee.trim().is_empty()).then(|| self.payee.trim()),
                        "start_height":start, "period_blocks":period, "recover_at":deadline,
                        "budget_micronoid":crate::app::parse_noid_amount(&self.budget)?, "max_fee_micronoid":max_fee,
                        "max_payout_micronoid":crate::app::parse_noid_amount(&self.max_payment)?,
                        "min_retained_micronoid":if self.reserve.trim() == "0" { 0 } else { crate::app::parse_noid_amount(&self.reserve)? }})
            }
            Kind::Recurring => {
                json!({"kind":"recurring_payment", "payer":active, "payee":self.authority.trim(),
                        "first_due_height":start, "period_blocks":period, "recover_at":deadline,
                        "payment_micronoid":crate::app::parse_noid_amount(&self.max_payment)?, "max_fee_micronoid":max_fee})
            }
            Kind::Vesting => {
                json!({"kind":"tranche_vesting", "beneficiary":self.authority.trim(),
                        "first_unlock_height":start, "period_blocks":period, "mature_at":deadline,
                        "tranche_micronoid":crate::app::parse_noid_amount(&self.max_payment)?, "max_fee_micronoid":max_fee})
            }
            Kind::Custom => unreachable!(),
        };
        Ok(definition)
    }

    fn require_active(&self, height: u64) -> Result<(), String> {
        if !self
            .protocol
            .as_ref()
            .is_some_and(|protocol| protocol.available(height))
        {
            return Err(
                "Contracts become available automatically at the v2 activation block.".into(),
            );
        }
        Ok(())
    }

    pub fn finish(&mut self, result: Result<Outcome, String>) {
        self.busy = false;
        match result {
            Err(error) => self.error = Some(error),
            Ok(Outcome::WithNotice(outcome, notice)) => {
                self.finish(Ok(*outcome));
                self.notice = Some(notice);
            }
            Ok(Outcome::Refreshed(outcome)) => {
                let tab = self.tab;
                let notice = self.notice.clone();
                self.finish(Ok(*outcome));
                self.tab = tab;
                self.notice = notice;
            }
            Ok(Outcome::WithActivity(outcome, operations)) => {
                let selected_txid = self
                    .selected_operation
                    .and_then(|i| self.operations.get(i))
                    .map(|op| op.txid.clone());
                self.finish(Ok(*outcome));
                self.operations = operations;
                self.selected_operation = selected_txid
                    .and_then(|txid| self.operations.iter().position(|op| op.txid == txid));
            }
            Ok(Outcome::Opened(file)) => {
                self.file_path = file.file_name.clone();
                self.opened = Some(file);
                self.tab = Tab::Open;
                self.notice = None;
            }
            Ok(Outcome::FundingReview {
                info,
                amount,
                fee,
                sender,
                creation,
            }) => {
                let summary = format!(
                    "Fund {} with {} NOID from {}. Network fee: {} NOID.",
                    info.address,
                    crate::model::format_micronoid(amount),
                    sender,
                    crate::model::format_micronoid(fee)
                );
                self.review = Some((
                    Request::Fund {
                        info,
                        amount,
                        fee,
                        sender,
                        creation,
                    },
                    summary,
                ));
            }
            Ok(Outcome::Home(protocol, library)) => {
                self.protocol = Some(protocol);
                self.library = library;
            }
            Ok(Outcome::Library(library)) => {
                if self.info.as_ref().is_some_and(|info| {
                    !library
                        .iter()
                        .any(|entry| entry.info.family_key() == info.family_key())
                }) {
                    // A removed entry must not be re-created by background polling.
                    self.info = None;
                    self.instances = None;
                    self.known_states = None;
                    self.candidate = None;
                    self.operations.clear();
                    self.selected_operation = None;
                    self.selected = None;
                    self.review = None;
                    self.name.clear();
                }
                self.library = library;
            }
            Ok(Outcome::Previewed {
                info,
                mut payload,
                preview,
            }) => {
                if let Err(error) = preview.bind(&mut payload) {
                    self.error = Some(error);
                    return;
                }
                self.review = Some((
                    Request::Call {
                        info,
                        payload,
                        authority: preview.authority.clone(),
                        recovery: preview.recovery,
                        preview,
                    },
                    "Review the node's exact call result below.".into(),
                ));
            }
            Ok(Outcome::Notice(notice)) => self.notice = Some(notice),
            Ok(Outcome::Related(states)) => self.known_states = Some(states),
            Ok(Outcome::Loaded(info, instances, library, states)) => {
                self.tab = Tab::Mine;
                let changed = self
                    .info
                    .as_ref()
                    .is_none_or(|previous| previous.address != info.address);
                if changed {
                    self.use_action = UseAction::Fund;
                    self.program_expanded = false;
                    self.amount.clear();
                    self.fee.clear();
                    self.payout.clear();
                    self.selected_operation = None;
                }
                // This is a fresh balance view, not a transaction receipt.
                // Do not carry an older submission's waiting message into it.
                self.notice = None;
                self.library = library;
                self.known_states = Some(states);
                self.candidate = self
                    .library
                    .iter()
                    .find(|entry| entry.info.family_key() == info.family_key())
                    .and_then(|entry| entry.candidate.clone());
                self.name = self
                    .library
                    .iter()
                    .find(|entry| entry.info.family_key() == info.family_key())
                    .map(|entry| entry.name.clone())
                    .unwrap_or_default();
                self.info = Some(info);
                if changed
                    || !instances
                        .slots
                        .iter()
                        .any(|slot| Some(slot.slot_index) == self.selected)
                {
                    self.selected = instances.slots.first().map(|slot| slot.slot_index);
                }
                self.instances = Some(instances);
                self.review = None;
            }
            Ok(Outcome::Submitted {
                txid,
                old_opening,
                successor,
            }) => {
                self.tab = Tab::Mine;
                self.last_poll = None;
                self.notice = Some(format!(
                    "Submitted: {txid}. Awaiting confirmation; refresh to read current balances."
                ));
                let _ = old_opening;
                self.candidate = successor;
                self.known_states = None;
                self.instances = None;
                self.selected = None;
            }
        }
    }
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.chars().count() > 64 || name.chars().any(char::is_control) {
        Err("Contract name must be at most 64 characters without control characters.".into())
    } else {
        Ok(())
    }
}

fn custom_example(active: &str, height: u64) -> String {
    serde_json::to_string_pretty(&json!({"kind":"custom_program", "definition":{
        "state":["0","0"],
        "program":[{"opcode":"add", "destination":"state0", "left":"state0", "right":"immediate",
            "predicate":{"source":"terminal","inverted":true}, "immediate":"1"}],
        "claim_authority":active, "recovery_authority":active,
        "claim_recipient":active, "recovery_recipient":active,
        "deadline_height":height.saturating_add(2880), "max_fee_micronoid":1000000,
        "max_payout_micronoid":3000000, "min_retained_micronoid":0,
        "claim_can_continue":true, "claim_can_close":true,
        "recovery_can_continue":false, "recovery_can_close":true,
        "unrestricted_payout_recipient":false
    }}))
    .unwrap()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn info() -> Info {
        let mut definition: Value =
            serde_json::from_str(&custom_example("spending-key", 50)).unwrap();
        let value = &mut definition["definition"];
        let keep = json!({"opcode":"keep", "destination":"state0", "left":"state0", "right":"state0",
            "predicate":{"source":"always","inverted":false}, "immediate":"0"});
        value["program"] = json!(vec![keep; 16]);
        value["abi_version"] = json!(3);
        value["address"] = json!("contract");
        value["opening_hex"] = json!("aa".repeat(699));
        value["code_id"] = json!("00".repeat(32));
        value["state_hex"] = json!("00".repeat(16));
        value["deadline_height"] = json!(100);
        value["recovery_authority"] = json!("recovery-key");
        value["claim_recipient"] = json!("fixed-payee");
        value["claim_can_close"] = json!(false);
        serde_json::from_value(value.clone()).unwrap()
    }

    fn loaded() -> State {
        let mut state = State {
            notice: Some("Earlier submission awaiting confirmation".into()),
            protocol: Some(Protocol {
                activation_height: Some(10),
                runtime_available: true,
                abi_version: 3,
            }),
            ..Default::default()
        };
        state.finish(Ok(Outcome::Loaded(
            info(),
            Instances {
                height: 50,
                slots: vec![Instance {
                    slot_index: 7,
                    value: 10_000_000,
                    creation_id: 123,
                }],
                next_slot: None,
            },
            Vec::new(),
            KnownStates {
                states: Vec::new(),
                height: 50,
                next_root: None,
            },
        )));
        assert!(state.notice.is_none());
        state.amount = "1".into();
        state
    }

    fn preview(payload: &Value) -> Preview {
        Preview {
            txid: "12".repeat(32),
            call_height: 51,
            authority: "spending-key".into(),
            recovery: false,
            terminal: false,
            fee_micronoid: 5800,
            retained_micronoid: 8_994_200,
            payout: serde_json::from_value(payload["payout"].clone()).unwrap(),
            successor: Some(info()),
        }
    }

    #[test]
    fn navigation_preserves_a_draft_and_selected_balance_during_rpc() {
        let mut state = loaded();
        prepare_funding(&mut state);
        assert!(state.review.is_some());
        let opening = state.info.as_ref().unwrap().opening_hex.clone();
        state.busy = true;
        for tab in [Tab::Open, Tab::Mine] {
            assert!(state
                .action(Action::SetTab(tab), "spending-key", 50)
                .unwrap()
                .is_none());
            assert_eq!(state.tab, tab);
            assert_eq!(state.info.as_ref().unwrap().opening_hex, opening);
            assert_eq!(state.selected, Some(7));
            assert_eq!(state.amount, "1");
            assert!(state.review.is_some());
            assert!(state.busy);
        }
    }

    #[test]
    fn editing_a_new_program_keeps_loaded_terms_but_cancels_the_old_review() {
        let mut state = loaded();
        prepare_funding(&mut state);
        state
            .action(Action::EditLoaded, "spending-key", 50)
            .unwrap();
        assert_eq!(state.tab, Tab::Create);
        assert!(state.review.is_none());
        assert!(state.info.is_some());
        state
            .action(Action::SetTab(Tab::Mine), "spending-key", 50)
            .unwrap();
        assert_eq!(state.tab, Tab::Mine);
        assert_eq!(state.selected, Some(7));
        state
            .action(Action::EditLoaded, "spending-key", 50)
            .unwrap();
        assert_eq!(state.tab, Tab::Create);
        assert_eq!(state.kind, Kind::Custom);
    }

    #[test]
    fn removing_a_contract_stops_automatic_refresh_without_discarding_a_draft() {
        let mut state = loaded();
        state.draft_name = "New draft".into();
        state.finish(Ok(Outcome::Library(vec![])));
        assert!(state.info.is_none() && state.selected.is_none());
        assert!(state
            .action(Action::Poll, "spending-key", 50)
            .unwrap()
            .is_none());
        assert_eq!(state.draft_name, "New draft");
    }

    #[test]
    fn opening_a_file_does_not_replace_the_selected_contract_before_acceptance() {
        let mut state = loaded();
        let old = state.info.as_ref().unwrap().address.clone();
        state.finish(Ok(Outcome::Opened(OpenedFile {
            file_name: "received.json".into(),
            name: "Received".into(),
            info: Some(info()),
            instances: None,
            proof: None,
            verified_call: None,
            operation: None,
        })));
        assert_eq!(state.tab, Tab::Open);
        assert_eq!(state.info.as_ref().unwrap().address, old);
        assert!(matches!(
            state
                .action(Action::AcceptFile, "spending-key", 50)
                .unwrap(),
            Some(Request::AcceptFile(_))
        ));
        state
            .action(Action::BrowseFile, "spending-key", 50)
            .unwrap();
        assert!(state.opened.is_none());
        state.finish(Err("Invalid file".into()));
        assert!(state.opened.is_none());
    }

    fn prepare_funding(state: &mut State) {
        let Some(Request::PrepareFunding {
            info,
            amount,
            fee: _,
            sender,
            creation,
        }) = state
            .action(Action::ReviewFund, "spending-key", 50)
            .unwrap()
        else {
            panic!("quote required")
        };
        state.finish(Ok(Outcome::FundingReview {
            info,
            amount,
            fee: 5800,
            sender,
            creation,
        }));
    }

    #[test]
    fn discovered_state_requires_a_fresh_balance_query_before_selecting_a_slot() {
        let mut state = loaded();
        let original = state.info.as_ref().unwrap().address.clone();
        let mut recovered = info();
        recovered.address = "recovered-state".into();
        state.known_states = Some(KnownStates {
            states: vec![KnownState {
                object: recovered,
                has_balance: true,
            }],
            height: 51,
            next_root: Some("ab".repeat(32)),
        });
        let Some(Request::Refresh(target, 0)) = state
            .action(Action::UseKnownState(0), "spending-key", 51)
            .unwrap()
        else {
            panic!("discovery must request current instances");
        };
        assert_eq!(target.address, "recovered-state");
        assert_eq!(state.info.as_ref().unwrap().address, original);
        assert!(state
            .action(Action::UseKnownState(1), "spending-key", 51)
            .is_err());
        assert!(
            matches!(state.action(Action::NextStates, "spending-key", 51).unwrap(),
            Some(Request::Related(_, cursor)) if cursor == "ab".repeat(32))
        );
    }

    #[test]
    fn complete_integer_program_is_required_before_funding() {
        let mut state = loaded();
        assert!(state.info.as_ref().unwrap().policy_only());
        state.info.as_mut().unwrap().state[0] = u64::MAX.to_string();
        state.info.as_mut().unwrap().program[0].immediate = ((1u64 << 53) + 1).to_string();
        state.info.as_mut().unwrap().program[0].opcode = "assert_less_or_equal".into();
        assert!(!state.info.as_ref().unwrap().policy_only());
        assert!(state.action(Action::ReviewFund, "payer", 50).is_ok());
        let text = serde_json::to_string(state.info.as_ref().unwrap()).unwrap();
        let restored: Info = serde_json::from_str(&text).unwrap();
        assert_eq!(restored.state[0], u64::MAX.to_string());
        assert_eq!(restored.program[0].immediate, "9007199254740993");
        state.action(Action::CancelReview, "payer", 50).unwrap();
        state.info.as_mut().unwrap().program.truncate(8);
        assert!(state.action(Action::ReviewFund, "payer", 50).is_err());
        assert!(state.review.is_none());
        let mut old = serde_json::to_value(info()).unwrap();
        old["program"][0]["opcode"] = json!(8);
        assert!(serde_json::from_value::<Info>(old).is_err());
    }

    #[test]
    fn call_review_uses_native_preview_and_binds_body_height_and_wallet() {
        let mut state = loaded();
        assert!(state
            .action(Action::ReviewClose, "spending-key", 50)
            .is_err());
        let Some(Request::Preview { info, payload }) =
            state.action(Action::ReviewPay, "spending-key", 50).unwrap()
        else {
            panic!("preview required")
        };
        assert!(state.review.is_none());
        assert_eq!(payload["creation_id"], 123);
        assert_eq!(payload["payout"]["address"], "fixed-payee");
        let reviewed = preview(&payload);
        state.finish(Ok(Outcome::Previewed {
            info: info.clone(),
            payload: payload.clone(),
            preview: reviewed.clone(),
        }));
        let Some(Request::Call {
            payload: signed, ..
        }) = state.action(Action::Confirm, "spending-key", 50).unwrap()
        else {
            panic!("reviewed call required")
        };
        assert_eq!(signed["expected_txid"], reviewed.txid);
        assert_eq!(signed["expected_call_height"], 51);
        assert_eq!(signed["fee_micronoid"], 5800);
        state.finish(Ok(Outcome::Previewed {
            info: info.clone(),
            payload: payload.clone(),
            preview: reviewed.clone(),
        }));
        assert!(state.action(Action::Confirm, "spending-key", 51).is_err());
        assert!(state.review.is_none());
        state.finish(Ok(Outcome::Previewed {
            info,
            payload,
            preview: reviewed,
        }));
        assert!(state.action(Action::Confirm, "different-key", 50).is_err());
    }

    #[test]
    fn mismatched_preview_cannot_be_confirmed_and_pending_state_is_not_promoted() {
        let mut state = loaded();
        let Some(Request::Preview { info, payload }) =
            state.action(Action::ReviewPay, "spending-key", 50).unwrap()
        else {
            panic!()
        };
        let mut bad = preview(&payload);
        bad.payout.as_mut().unwrap().amount_micronoid += 1;
        state.finish(Ok(Outcome::Previewed {
            info,
            payload,
            preview: bad,
        }));
        assert!(state.review.is_none());
        assert!(state.error.is_some());
        let mut candidate = super::tests::info();
        candidate.address = "candidate".into();
        state.finish(Ok(Outcome::Submitted {
            txid: "12".repeat(32),
            old_opening: Some("opening".into()),
            successor: Some(candidate),
        }));
        assert_eq!(state.info.as_ref().unwrap().address, "contract");
        assert_eq!(state.candidate.as_ref().unwrap().address, "candidate");
        assert!(state.instances.is_none());
    }

    #[test]
    fn activation_and_missing_runtime_gate_value_operations_only() {
        let mut state = loaded();
        assert!(state.action(Action::ReviewFund, "payer", 8).is_err());
        assert!(state.action(Action::ReviewFund, "payer", 9).is_ok());
        state.action(Action::CancelReview, "payer", 9).unwrap();
        state.protocol.as_mut().unwrap().runtime_available = false;
        assert!(state.action(Action::ReviewFund, "payer", 20).is_err());
        assert!(matches!(
            state.action(Action::Save, "payer", 20).unwrap(),
            Some(Request::Save(_))
        ));
        state.protocol.as_mut().unwrap().runtime_available = true;
        prepare_funding(&mut state);
        assert!(state.action(Action::Confirm, "other-key", 20).is_err());
    }

    #[test]
    fn scheduled_templates_and_custom_editor_preserve_precise_terms() {
        let mut state = loaded();
        state.authority = "recipient".into();
        state.deadline = "300".into();
        state.start = "100".into();
        state.period = "20".into();
        for (kind, tag) in [
            (Kind::Budget, "period_budget_wallet"),
            (Kind::Recurring, "recurring_payment"),
            (Kind::Vesting, "tranche_vesting"),
        ] {
            state.kind = kind;
            let Some(Request::SaveDraft { definition, .. }) =
                state.action(Action::Create, "active-key", 50).unwrap()
            else {
                panic!()
            };
            assert_eq!(definition["kind"], tag);
            assert_eq!(definition["period_blocks"], 20);
            if kind == Kind::Budget {
                assert_eq!(definition["recovery_key"], "active-key");
            }
            if kind == Kind::Recurring {
                assert_eq!(definition["payer"], "active-key");
            }
            if kind == Kind::Vesting {
                assert_eq!(definition["beneficiary"], "recipient");
            }
        }
        state.action(Action::EditLoaded, "payer", 50).unwrap();
        let Some(Request::SaveDraft { definition, .. }) =
            state.action(Action::Create, "payer", 50).unwrap()
        else {
            panic!()
        };
        assert_eq!(definition["kind"], "custom_program");
        assert!(definition["definition"].get("address").is_none());
        assert!(definition["definition"].get("abi_version").is_none());
        assert_eq!(
            definition["definition"]["program"]
                .as_array()
                .unwrap()
                .len(),
            16
        );
        assert_eq!(state.info.as_ref().unwrap().address, "contract");
    }
}
