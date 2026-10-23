// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Height-selected proving and verification authority for the node. The
//! transition release carries both banks; each v2 origin is independently
//! authenticated and keyed by its exact legacy boundary and successor bank.
//! Legacy and retirement certificates mint the same verified origin capability.

use noid_chain::{
    consensus::{forks::ACTIVE_SCHEDULE, params},
    BlockHeader,
};
use noid_recursive::acceptance::history_step::{
    self as legacy,
    v2::{banked as v2, capacity_banked as v21},
};
mod origin;
pub use origin::{ForkOrigin, VerifiedForkOrigin};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
};

const CACHED_ORIGINS: usize = 16;
const CACHED_ORIGIN_BYTES: usize = 64 * 1024 * 1024;
static NEXT_ORIGIN_FILE: AtomicU64 = AtomicU64::new(0);

struct CachedOrigin {
    checked: Arc<VerifiedForkOrigin>,
    certificate: Arc<[u8]>,
    retired: bool,
}

pub struct HistoryProtocolRuntime {
    legacy: Option<Arc<legacy::HistoryStepRuntime>>,
    v2: Option<Arc<v2::Runtime>>,
    authorization: Option<Arc<v2::Runtime>>,
    finance: Option<Arc<v21::Runtime>>,
    authorization_ghost:
        OnceLock<Result<Arc<legacy::PreparedHistoryStepGhostAuthorization>, String>>,
    origins: Mutex<VecDeque<CachedOrigin>>,
    origin_directory: PathBuf,
    origin_files: Mutex<()>,
    canonical_store: OnceLock<noid_chain::storage::MdbxStore>,
    retirement_keys: Option<v2::PinnedRetirementKeys>,
    legacy_matrix_cache_available: bool,
    large_v2_mining: bool,
}

impl HistoryProtocolRuntime {
    pub fn new(
        legacy: Option<Arc<legacy::HistoryStepRuntime>>,
        v2: Option<Arc<v2::Runtime>>,
        origin_directory: PathBuf,
    ) -> Result<Self, String> {
        if legacy.is_none() && v2.is_none() {
            return Err("no history bank configured".into());
        }
        if let Some(runtime) = v2.as_ref() {
            if runtime.bank().config().schedule() != ACTIVE_SCHEDULE
                || runtime
                    .bank()
                    .config()
                    .class(v2::Class::Small)
                    .authorization_activation()
                    .is_some()
            {
                return Err("v2 runtime fork schedule differs from this executable".into());
            }
        }
        Ok(Self {
            legacy,
            v2,
            authorization: None,
            finance: None,
            authorization_ghost: OnceLock::new(),
            origins: Mutex::new(VecDeque::new()),
            origin_directory,
            origin_files: Mutex::new(()),
            canonical_store: OnceLock::new(),
            retirement_keys: None,
            legacy_matrix_cache_available: true,
            large_v2_mining: false,
        })
    }

    pub fn with_authorization_runtime(
        mut self,
        runtime: Option<Arc<v2::Runtime>>,
    ) -> Result<Self, String> {
        if runtime.is_some() && self.finance.is_some() {
            return Err("multiple authorization banks configured".into());
        }
        if let Some(updated) = &runtime {
            let previous = self.v2()?;
            if updated.bank().config().schedule() != ACTIVE_SCHEDULE
                || updated
                    .bank()
                    .config()
                    .class(v2::Class::Small)
                    .authorization_activation()
                    != params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT
                || params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT.is_none()
            {
                return Err("authorization runtime differs from the executable schedule".into());
            }
            for class in v2::Class::ALL {
                let old = previous.bank().config().class(class);
                let new = updated.bank().config().class(class);
                if (old.pages(), old.max_live_inputs(), old.contract_slots())
                    != (new.pages(), new.max_live_inputs(), new.contract_slots())
                {
                    return Err("authorization runtime resource limits differ".into());
                }
            }
        } else if params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT.is_some() && self.finance.is_none()
        {
            return Err("scheduled authorization runtime unavailable".into());
        }
        self.authorization = runtime;
        Ok(self)
    }

    pub fn with_finance_runtime(
        mut self,
        runtime: Option<Arc<v21::Runtime>>,
    ) -> Result<Self, String> {
        if runtime.is_some() && self.authorization.is_some() {
            return Err("multiple authorization banks configured".into());
        }
        if let Some(updated) = &runtime {
            let previous = self.v2()?;
            let config = updated.bank().config();
            if config.schedule() != ACTIVE_SCHEDULE
                || config.class(v21::Class::Small).authorization_activation()
                    != params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT
                || params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT.is_none()
            {
                return Err("native runtime differs from the executable schedule".into());
            }
            for (old_class, new_class) in [
                (v2::Class::Small, v21::Class::Small),
                (v2::Class::Large, v21::Class::Large),
            ] {
                let old = previous.bank().config().class(old_class);
                let new = config.class(new_class);
                if (old.pages(), old.max_live_inputs(), old.contract_slots())
                    != (new.pages(), new.max_live_inputs(), new.contract_slots())
                {
                    return Err("native runtime ordinary resource limits differ".into());
                }
            }
        }
        self.finance = runtime;
        Ok(self)
    }

    pub fn uses_finance_runtime(&self, height: u64) -> bool {
        self.finance.is_some() && params::v2_1_active(height)
    }

    pub fn finance_at(&self, height: u64) -> Result<&v21::Runtime, String> {
        if !params::v2_1_active(height) {
            return Err("native runtime requested before activation".into());
        }
        self.finance
            .as_deref()
            .ok_or_else(|| "scheduled native runtime unavailable".into())
    }

    pub fn finance_config(&self) -> Option<v21::Config> {
        self.finance.as_ref().map(|runtime| runtime.bank().config())
    }

    pub fn selection_config_at(&self, height: u64) -> Result<v2::Config, String> {
        if self.uses_finance_runtime(height) {
            let config = self.finance_at(height)?.bank().config();
            v2::Config::new(
                config.class(v21::Class::Small),
                config.class(v21::Class::Large),
            )
            .map_err(|e| e.to_string())
        } else {
            Ok(self.v2_at(height)?.bank().config())
        }
    }

    pub fn proof_class_config(
        &self,
        height: u64,
        wire_id: u8,
    ) -> Result<noid_recursive::acceptance::history_step::v2::V2Config, String> {
        if self.uses_finance_runtime(height) {
            let class = v21::Class::from_wire(wire_id).map_err(|e| e.to_string())?;
            Ok(self.finance_at(height)?.bank().config().class(class))
        } else {
            let class = v2::Class::from_wire(wire_id).map_err(|e| e.to_string())?;
            Ok(self.v2_at(height)?.bank().config().class(class))
        }
    }

    pub fn require_v2_height(&self, height: u64) -> Result<(), String> {
        if self.uses_finance_runtime(height) {
            self.finance_at(height).map(|_| ())
        } else {
            self.v2_at(height).map(|_| ())
        }
    }

    pub fn v2_at(&self, height: u64) -> Result<&v2::Runtime, String> {
        if params::owner_authorization_version(height) == noid_tx::OwnerAuthorizationVersion::V4 {
            self.authorization
                .as_deref()
                .ok_or_else(|| "scheduled authorization runtime unavailable".into())
        } else {
            self.v2()
        }
    }

    pub fn authorization_ghost(
        &self,
    ) -> Result<Arc<legacy::PreparedHistoryStepGhostAuthorization>, String> {
        self.authorization_ghost
            .get_or_init(|| {
                let version = noid_tx::OwnerAuthorizationVersion::V4;
                let proof =
                    noid_gkr::ghost_tx::prove_selected_ghost_authorization_for_version(version)
                        .map_err(|e| e.to_string())?;
                legacy::prepare_history_step_ghost_authorization_for_version(proof, version)
                    .map(Arc::new)
                    .map_err(|e| e.to_string())
            })
            .clone()
    }

    /// Producer policy only. Every node verifies both v2 classes regardless
    /// of this explicit server opt-in; pre-v2 calibration is unaffected.
    pub fn with_large_v2_mining(mut self, allowed: bool) -> Self {
        self.large_v2_mining = allowed;
        self
    }

    pub const fn large_v2_mining_allowed(&self) -> bool {
        self.large_v2_mining
    }

    /// Preparation hint for the wallet. This grants no verification authority;
    /// the configured matrix source still decides which rows can be loaded.
    pub fn with_legacy_matrix_cache_available(mut self, available: bool) -> Self {
        self.legacy_matrix_cache_available = available;
        self
    }

    pub fn needs_legacy_matrix_cache(&self, candidate_height: u64) -> bool {
        self.legacy_matrix_cache_available
            && self.legacy.is_some()
            && !params::v2_active(candidate_height)
    }

    pub fn with_retirement_keys(mut self, keys: v2::PinnedRetirementKeys) -> Result<Self, String> {
        if keys.legacy_bank_digest() != self.legacy()?.bank().digest() {
            return Err("retirement keys belong to a different legacy bank".into());
        }
        self.retirement_keys = Some(keys);
        Ok(self)
    }

    /// Attach the node's canonical store before accepting peers. Disk cache
    /// eviction protects its selected origin even while other valid branches
    /// are being verified outside the sole chain writer.
    pub fn attach_canonical_store(
        &self,
        store: noid_chain::storage::MdbxStore,
    ) -> Result<(), String> {
        self.canonical_store
            .set(store)
            .map_err(|_| "canonical origin store already attached".into())
    }

    fn selected_origin_binding(&self) -> Result<Option<[u8; 32]>, String> {
        let Some(store) = self.canonical_store.get() else {
            return Ok(None);
        };
        let Some((height, hash)) = store.get_chain_tip().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        if !params::v2_active(height) {
            return Ok(None);
        }
        let Some(terminal) = store
            .get_history_step_terminal_at(height, hash)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        Ok(self
            .requested_origin(&terminal)?
            .map(|origin| origin.request_binding()))
    }

    pub fn legacy(&self) -> Result<&legacy::HistoryStepRuntime, String> {
        self.legacy
            .as_deref()
            .ok_or_else(|| "legacy HistoryStep runtime unavailable".into())
    }

    pub fn v2(&self) -> Result<&v2::Runtime, String> {
        self.v2
            .as_deref()
            .ok_or_else(|| "scheduled v2 HistoryStep runtime unavailable".into())
    }

    /// Full immutable budgets from the authenticated bank. The mempool and
    /// producer reserve any additional system page at the candidate height.
    pub fn v2_admission_budgets(&self) -> Option<[noid_chain::mempool::BlockSelectionBudget; 2]> {
        if let Some(runtime) = &self.finance {
            let config = runtime.bank().config();
            return Some(
                [v21::Class::Small, v21::Class::Large]
                    .map(|class| crate::template::v2_full_selection_budget(config.class(class))),
            );
        }
        let runtime = self.authorization.as_deref().or(self.v2.as_deref())?;
        let config = runtime.bank().config();
        Some(
            v2::Class::ALL
                .map(|class| crate::template::v2_full_selection_budget(config.class(class))),
        )
    }

    pub fn prepare_v2_matrix_cache(&self, class: v2::Class) -> Result<(), String> {
        self.v2()?
            .prepare_matrix_cache(class)
            .map_err(|e| e.to_string())
    }

    pub fn v21_native_admission_budget(&self) -> Option<noid_chain::mempool::BlockSelectionBudget> {
        let runtime = self.finance.as_ref()?;
        Some(crate::template::v2_full_selection_budget(
            runtime.bank().config().class(v21::Class::Native),
        ))
    }

    pub fn prepare_matrix_cache(
        &self,
        class: noid_recursive::CanonicalHistoryStepClassId,
    ) -> Result<(), String> {
        self.legacy()?
            .prepare_matrix_cache(class)
            .map_err(|e| e.to_string())
    }

    fn cached(&self, requested: &ForkOrigin) -> Result<Option<Arc<VerifiedForkOrigin>>, String> {
        let cache = self
            .origins
            .lock()
            .map_err(|_| "fork-origin cache poisoned")?;
        Ok(cache
            .iter()
            .find(|entry| entry.checked.origin() == requested)
            .map(|entry| Arc::clone(&entry.checked)))
    }

    fn cached_request(&self, request: [u8; 32]) -> Result<Option<Arc<VerifiedForkOrigin>>, String> {
        Ok(self
            .origins
            .lock()
            .map_err(|_| "fork-origin cache poisoned")?
            .iter()
            .find(|entry| entry.checked.origin().request_binding() == request)
            .map(|entry| Arc::clone(&entry.checked)))
    }

    fn authorization_predecessor(
        &self,
        certificate: &v2::AuthorizationOriginCertificate,
    ) -> Result<Arc<VerifiedForkOrigin>, String> {
        let request = certificate.previous_origin_request();
        if let Some(checked) = self.cached_request(request)? {
            return Ok(checked);
        }
        let bytes = self
            .origin_bytes(request)?
            .unwrap_or_else(|| certificate.previous_origin_bytes().to_vec());
        if !(bytes.starts_with(b"O1V2OR01") || bytes.starts_with(b"O1V2OR02")) {
            return Err("authorization predecessor format is not canonical".into());
        }
        let checked = self.install_origin_bytes(&bytes)?;
        if checked.origin().request_binding() != request {
            return Err("authorization predecessor differs from its certificate".into());
        }
        Ok(checked)
    }

    pub fn has_verified_origin(&self, requested: &ForkOrigin) -> Result<bool, String> {
        Ok(self.cached(requested)?.is_some())
    }

    /// Certificate transport is untrusted. Cache only after complete legacy
    /// proof/matrix verification, never on decoding or a matching header alone.
    pub fn install_legacy_origin(
        &self,
        certificate: v2::LegacyOriginCertificate,
    ) -> Result<Arc<VerifiedForkOrigin>, String> {
        let checked = certificate
            .verify(self.legacy()?, self.v2()?.bank())
            .map_err(|e| e.to_string())?;
        self.cache_origin(
            Arc::new(VerifiedForkOrigin::from_v2(checked)),
            certificate.to_bytes(),
            false,
        )
    }

    /// Both formats authenticate the exact origin. Retirement verification
    /// closes every live old matrix claim under independently pinned keys.
    pub fn install_origin_bytes(&self, bytes: &[u8]) -> Result<Arc<VerifiedForkOrigin>, String> {
        if bytes.starts_with(b"O1A4OR01") {
            let certificate =
                v2::AuthorizationOriginCertificate::from_bytes(bytes).map_err(|e| e.to_string())?;
            let previous_origin = self.authorization_predecessor(&certificate)?;
            let previous_bytes = self
                .origin_bytes(previous_origin.origin().request_binding())?
                .ok_or("verified predecessor certificate unavailable")?;
            let certificate = certificate
                .with_previous_origin_bytes(previous_bytes)
                .map_err(|e| e.to_string())?;
            let encoded = certificate.to_bytes();
            let checked = if let Some(next) = self.finance.as_deref() {
                let certificate = v21::AuthorizationOriginCertificate::from_bytes(&encoded)
                    .map_err(|e| e.to_string())?;
                VerifiedForkOrigin::from_v21(
                    certificate
                        .verify(self.v2()?, previous_origin.v2()?, next.bank())
                        .map_err(|e| e.to_string())?,
                )
            } else {
                let next = self
                    .authorization
                    .as_deref()
                    .ok_or("scheduled authorization runtime unavailable")?;
                VerifiedForkOrigin::from_v2(
                    certificate
                        .verify(self.v2()?, previous_origin.v2()?, next.bank())
                        .map_err(|e| e.to_string())?,
                )
            };
            let retired = certificate.previous_origin_bytes().starts_with(b"O1V2OR02");
            let checked = self.cache_origin(Arc::new(checked), encoded, retired)?;
            self.v2()?.release_cached_matrices();
            Ok(checked)
        } else if bytes.starts_with(b"O1V2OR02") {
            let keys = self
                .retirement_keys
                .as_ref()
                .ok_or("release-pinned retirement keys unavailable")?;
            let certificate =
                v2::RetirementOriginCertificate::from_bytes(bytes).map_err(|e| e.to_string())?;
            let checked = certificate
                .verify(self.legacy()?, self.v2()?.bank(), keys)
                .map_err(|e| e.to_string())?;
            self.cache_origin(
                Arc::new(VerifiedForkOrigin::from_v2(checked)),
                bytes.to_vec(),
                true,
            )
        } else {
            self.install_legacy_origin(
                v2::LegacyOriginCertificate::from_bytes(bytes).map_err(|e| e.to_string())?,
            )
        }
    }

    fn cache_origin(
        &self,
        checked: Arc<VerifiedForkOrigin>,
        certificate: Vec<u8>,
        retired: bool,
    ) -> Result<Arc<VerifiedForkOrigin>, String> {
        if certificate.len() > v2::MAX_RETIREMENT_ORIGIN_BYTES {
            return Err("fork-origin cache byte bound".into());
        }
        let mut cache = self
            .origins
            .lock()
            .map_err(|_| "fork-origin cache poisoned")?;
        if let Some(index) = cache
            .iter()
            .position(|entry| entry.checked.origin() == checked.origin())
        {
            if cache[index].retired || !retired {
                return Ok(Arc::clone(&cache[index].checked));
            }
            // Upgrade transport to the checked retirement proof so later
            // nodes can authenticate the same origin without old rows.
            cache.remove(index);
        }
        while cache.len() >= CACHED_ORIGINS
            || cache
                .iter()
                .map(|entry| entry.certificate.len())
                .sum::<usize>()
                + certificate.len()
                > CACHED_ORIGIN_BYTES
        {
            cache.pop_front();
        }
        cache.push_back(CachedOrigin {
            checked: Arc::clone(&checked),
            certificate: Arc::from(certificate),
            retired,
        });
        Ok(checked)
    }

    /// Retain a fully verified candidate before a possible canonical commit.
    /// Candidates have a fixed disk bound; eviction protects the selected
    /// chain's certificate. Verification alone cannot grow disk use forever.
    pub fn retain_origin(&self, origin: &VerifiedForkOrigin) -> Result<(), String> {
        let bytes = self
            .origin_bytes(origin.origin().request_binding())?
            .ok_or("verified origin certificate unavailable")?;
        let mut ancestors = Vec::new();
        if bytes.starts_with(b"O1A4OR01") {
            let certificate = v2::AuthorizationOriginCertificate::from_bytes(&bytes)
                .map_err(|e| e.to_string())?;
            let predecessor = self.authorization_predecessor(&certificate)?;
            if predecessor.origin().request_binding() != certificate.previous_origin_request() {
                return Err("authorization predecessor differs from its certificate".into());
            }
            self.retain_origin(&predecessor)?;
            ancestors.push(self.origin_path(certificate.previous_origin_request()));
        }
        let _files = self
            .origin_files
            .lock()
            .map_err(|_| "fork-origin files poisoned")?;
        let selected = self.selected_origin_binding()?;
        if let Some(selected) = selected {
            if selected != origin.origin().request_binding() {
                if let Some(selected_bytes) = read_optional_bounded(
                    &self.origin_path(selected),
                    v2::MAX_AUTHORIZATION_ORIGIN_BYTES,
                )? {
                    if selected_bytes.starts_with(b"O1A4OR01") {
                        let certificate =
                            v2::AuthorizationOriginCertificate::from_bytes(&selected_bytes)
                                .map_err(|e| e.to_string())?;
                        ancestors.push(self.origin_path(certificate.previous_origin_request()));
                    }
                }
            }
        }
        std::fs::create_dir_all(&self.origin_directory).map_err(|e| e.to_string())?;
        let path = self.origin_path(origin.origin().request_binding());
        let existing = read_optional_bounded(&path, v2::MAX_RETIREMENT_ORIGIN_BYTES)?;
        let checked_retirement_already_retained = existing.as_ref().is_some_and(|stored| {
            stored.starts_with(b"O1V2OR02")
                && !bytes.starts_with(b"O1V2OR02")
                && self.retirement_keys.is_some()
                && self
                    .install_origin_bytes(stored)
                    .is_ok_and(|checked| checked.origin() == origin.origin())
        });
        if existing.as_deref() == Some(bytes.as_slice()) || checked_retirement_already_retained {
            return prune_origin_files(
                &self.origin_directory,
                &path,
                selected.map(|id| self.origin_path(id)).as_deref(),
                &ancestors,
            );
        }
        let (temporary, mut file) = loop {
            let temporary = path.with_extension(format!(
                "{}.{}.partial",
                std::process::id(),
                NEXT_ORIGIN_FILE.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => break (temporary, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.to_string()),
            }
        };
        let result = (|| {
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            std::fs::rename(&temporary, &path).map_err(|e| e.to_string())?;
            prune_origin_files(
                &self.origin_directory,
                &path,
                selected.map(|id| self.origin_path(id)).as_deref(),
                &ancestors,
            )?;
            #[cfg(unix)]
            std::fs::File::open(&self.origin_directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    fn origin_path(&self, request: [u8; 32]) -> PathBuf {
        self.origin_directory
            .join(format!("{}.origin", hex::encode(request)))
    }

    pub fn origin_bytes(&self, request: [u8; 32]) -> Result<Option<Vec<u8>>, String> {
        {
            let cache = self
                .origins
                .lock()
                .map_err(|_| "fork-origin cache poisoned")?;
            if let Some(entry) = cache
                .iter()
                .find(|entry| entry.checked.origin().request_binding() == request)
            {
                return Ok(Some(entry.certificate.to_vec()));
            }
        }
        read_optional_bounded(&self.origin_path(request), v2::MAX_RETIREMENT_ORIGIN_BYTES)
    }

    pub fn verified_origin(
        &self,
        requested: &ForkOrigin,
    ) -> Result<Arc<VerifiedForkOrigin>, String> {
        if let Some(checked) = self.cached(requested)? {
            return Ok(checked);
        }
        let bytes = self
            .origin_bytes(requested.request_binding())?
            .ok_or_else(|| {
                format!(
                    "fork origin {} requires its authenticated certificate",
                    hex::encode(requested.request_binding())
                )
            })?;
        let checked = self.install_origin_bytes(&bytes)?;
        if checked.origin() != requested {
            return Err("fork certificate belongs to a different origin".into());
        }
        Ok(checked)
    }

    /// Untrusted fetch key only; proof acceptance still calls verify_terminal.
    pub fn requested_origin(&self, bytes: &[u8]) -> Result<Option<ForkOrigin>, String> {
        let metadata = noid_chain::history_step::HistoryStepTerminalMetadata::decode_prefix(bytes)
            .map_err(|e| e.to_string())?;
        let height = metadata.terminal_height();
        if !params::v2_active(height) {
            return Ok(None);
        }
        if self.uses_finance_runtime(height) {
            let runtime = self.finance_at(height)?;
            v21::decode_terminal(runtime, bytes)
                .and_then(|terminal| terminal.claimed_origin(runtime))
                .map(|origin| Some(origin.into()))
                .map_err(|e| e.to_string())
        } else {
            let runtime = self.v2_at(height)?;
            v2::decode_terminal(runtime, bytes)
                .and_then(|terminal| terminal.claimed_origin(runtime))
                .map(|origin| Some(origin.into()))
                .map_err(|e| e.to_string())
        }
    }

    pub fn origin_for_parent(
        &self,
        parent: &BlockHeader,
        epoch: &BlockHeader,
        terminal: &[u8],
    ) -> Result<Arc<VerifiedForkOrigin>, String> {
        let child = parent
            .height
            .checked_add(1)
            .ok_or("parent height exhausted")?;
        if Some(child) == params::V2_ACTIVATION_HEIGHT {
            let certificate = v2::LegacyOriginCertificate::new(*parent, *epoch, terminal.to_vec())
                .map_err(|e| e.to_string())?;
            let checked = self.install_legacy_origin(certificate)?;
            self.retain_origin(&checked)?;
            Ok(checked)
        } else if Some(child) == params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT {
            let runtime = self.v2()?;
            let decoded = v2::decode_terminal(runtime, terminal).map_err(|e| e.to_string())?;
            let previous = decoded.claimed_origin(runtime).map_err(|e| e.to_string())?;
            let checked_previous = self.verified_origin(&previous.clone().into())?;
            let previous_bytes = self
                .origin_bytes(checked_previous.origin().request_binding())?
                .ok_or("previous origin certificate unavailable")?;
            let certificate = v2::AuthorizationOriginCertificate::new(
                *parent,
                *epoch,
                terminal.to_vec(),
                previous_bytes,
                previous.request_binding(),
            )
            .map_err(|e| e.to_string())?;
            let checked = self.install_origin_bytes(&certificate.to_bytes())?;
            self.retain_origin(&checked)?;
            Ok(checked)
        } else if params::v2_active(parent.height) {
            let requested = self
                .requested_origin(terminal)?
                .ok_or("v2 parent origin unavailable")?;
            self.verified_origin(&requested)
        } else {
            Err("v2 parent requested before the fork".into())
        }
    }

    pub fn verify_terminal(
        &self,
        bytes: &[u8],
        header: &BlockHeader,
        epoch: &BlockHeader,
    ) -> Result<(), String> {
        if self.uses_finance_runtime(header.height) {
            let runtime = self.finance_at(header.height)?;
            let terminal = v21::decode_terminal(runtime, bytes).map_err(|e| e.to_string())?;
            let requested: ForkOrigin = terminal
                .claimed_origin(runtime)
                .map_err(|e| e.to_string())?
                .into();
            let origin = self.verified_origin(&requested)?;
            let _accepted = v21::verify_terminal(runtime, origin.v21()?, &terminal, header, epoch)
                .map_err(|e| e.to_string())?;
            self.retain_origin(&origin)?;
        } else if params::v2_active(header.height) {
            let runtime = self.v2_at(header.height)?;
            let terminal = v2::decode_terminal(runtime, bytes).map_err(|e| e.to_string())?;
            let requested: ForkOrigin = terminal
                .claimed_origin(runtime)
                .map_err(|e| e.to_string())?
                .into();
            let origin = self.verified_origin(&requested)?;
            let _accepted = v2::verify_terminal(runtime, origin.v2()?, &terminal, header, epoch)
                .map_err(|e| e.to_string())?;
            self.retain_origin(&origin)?;
        } else {
            let _accepted =
                legacy::decode_verify_history_step_terminal(self.legacy()?, bytes, header, epoch)
                    .map_err(|e| e.to_string())?;
            if self.v2.is_some() && header.height.checked_add(1) == params::V2_ACTIVATION_HEIGHT {
                let certificate = v2::LegacyOriginCertificate::new(*header, *epoch, bytes.to_vec())
                    .map_err(|e| e.to_string())?;
                self.install_legacy_origin(certificate)?;
            }
        }
        Ok(())
    }
}

fn prune_origin_files(
    directory: &Path,
    newest: &Path,
    selected: Option<&Path>,
    ancestors: &[PathBuf],
) -> Result<(), String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(key) = name.to_str().and_then(|s| s.strip_suffix(".origin")) else {
            continue;
        };
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !metadata.is_file() {
            continue;
        }
        files.push((metadata.modified().map_err(|e| e.to_string())?, path));
    }
    let excess = files.len().saturating_sub(CACHED_ORIGINS);
    files.sort_unstable();
    for (_, path) in files
        .into_iter()
        .filter(|(_, path)| {
            path != newest && Some(path.as_path()) != selected && !ancestors.contains(path)
        })
        .take(excess)
    {
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn read_optional_bounded(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("fork-origin file bound".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("fork-origin file grew beyond its bound".into());
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_origin_files_are_bounded_and_selected_certificate_survives() {
        let directory = tempfile::tempdir().unwrap();
        let selected = directory
            .path()
            .join(format!("{}.origin", hex::encode([0; 32])));
        std::fs::write(&selected, b"selected certificate").unwrap();
        let unrelated = directory.path().join("operator-note.txt");
        std::fs::write(&unrelated, b"untouched").unwrap();
        for id in 1..64u8 {
            let newest = directory
                .path()
                .join(format!("{}.origin", hex::encode([id; 32])));
            std::fs::write(&newest, [id]).unwrap();
            prune_origin_files(directory.path(), &newest, Some(&selected), &[]).unwrap();
            assert_eq!(std::fs::read(&selected).unwrap(), b"selected certificate");
            assert_eq!(std::fs::read(&newest).unwrap(), [id]);
            assert!(std::fs::read_dir(directory.path()).unwrap().count() <= CACHED_ORIGINS + 1);
        }
        assert_eq!(std::fs::read(unrelated).unwrap(), b"untouched");
    }
}
