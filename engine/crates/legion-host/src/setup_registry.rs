//! Canonical, fail-closed setup and durable-state registry.
//!
//! This module owns only mechanical lifecycle state, client registrations, and
//! verification facts. It never owns Legion capability or policy semantics.

use crate::digest_bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const SETUP_REGISTRY_SCHEMA_VERSION: u32 = 1;
const OWNER_MARKER: &str = "legion-host-setup-registry-v1";
const SIGNING_RECEIPT_RELATIVE_PATH: &str = "qualification/signing-receipt.json";
const RIGHTKIT_AX_VERSION: &str = "0.2.0";
const RIGHTKIT_AX_SOURCE_COMMIT: &str = "01f52555202da3dffc6b649ca44e803b55238081";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundRelease {
    pub release_version: String,
    pub runtime_digest: String,
    pub capability_catalog_hash: String,
    pub mcp_tool_schema_hash: String,
    pub declarative_asset_schema_hash: String,
    pub state_compatibility: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupAction {
    Preview,
    Apply,
    Status,
    Repair,
    Disable,
    Remove,
    Purge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClientSelector {
    AllSupported,
    ClientId(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEvidence {
    pub client_id: String,
    pub detected: bool,
    pub mechanisms: Vec<String>,
    pub command_proof_ref: Option<String>,
    pub qualification_evidence_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRequest {
    pub action: SetupAction,
    pub selector: ClientSelector,
    pub release: BoundRelease,
    pub platform_state_root: PathBuf,
    pub client_evidence: Vec<ClientEvidence>,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectedClient {
    pub client_id: String,
    pub selected_mechanism: String,
    pub fidelity: String,
    pub missing_surfaces: Vec<String>,
    pub remediation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedMutation {
    pub target: PathBuf,
    pub operation: String,
    pub digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecord {
    pub target: PathBuf,
    pub snapshot: PathBuf,
    pub digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPlan {
    pub generation: String,
    pub snapshot: PathBuf,
    pub release: BoundRelease,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalQualificationStatus {
    Qualified,
    ExternalQualificationBlocked,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalQualification {
    pub status: ExternalQualificationStatus,
    pub missing_evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupPreview {
    pub plan_id: String,
    pub plan_digest: String,
    pub request: SetupRequest,
    pub clients: Vec<DetectedClient>,
    pub mutations: Vec<PlannedMutation>,
    pub backups: Vec<BackupRecord>,
    pub rollback: RollbackPlan,
    pub external_qualification: ExternalQualification,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanConfirmation {
    pub plan_id: String,
    pub plan_digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmedSetup {
    pub preview: SetupPreview,
    pub confirmation: PlanConfirmation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStatus {
    pub client_id: String,
    pub installed: bool,
    pub fidelity: String,
    pub bound_release: Option<BoundRelease>,
    pub missing_surfaces: Vec<String>,
    pub remediation: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupExecution {
    pub action: SetupAction,
    pub generation: Option<String>,
    pub clients: Vec<ClientStatus>,
    pub remediation: Vec<String>,
    pub external_qualification: ExternalQualification,
    pub purged: Vec<PathBuf>,
    pub retained: Vec<PathBuf>,
    #[serde(rename = "ownershipProof")]
    pub ownership_proof: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReport {
    pub recovered_generation: Option<String>,
    pub remediation: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLease {
    pub lease_id: String,
    pub client_id: String,
    pub generation: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateLock {
    pub lock_path: PathBuf,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupState {
    pub schema_version: u32,
    pub migration_generation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetupErrorCode {
    ClientNotDetected,
    ClientMechanismUnsupported,
    PlanConfirmationRequired,
    PlanStale,
    ConfigOwnershipConflict,
    ConfigParseRefused,
    PathEscapeRefused,
    SourceCheckoutReferenceRefused,
    CommandResolutionFailed,
    ReleaseBindingMismatch,
    VerificationFailed,
    RollbackFailed,
    PurgeOwnershipUnproven,
    PlatformStateRootInvalid,
    StateMetadataInvalid,
    StateSerializationFailed,
    StateLockUnavailable,
    RuntimeLeaseActive,
    SnapshotFailed,
    JournalIncomplete,
    RecoveryFailed,
    ExternalQualificationBlocked,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupError {
    pub code: SetupErrorCode,
    pub remediation: String,
}
impl Display for SetupError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.remediation)
    }
}
impl std::error::Error for SetupError {}

pub trait SetupStore {
    fn platform_state_root(&self) -> &Path;
    fn load_state(&self) -> Result<Option<SetupState>, SetupError>;
    fn write_state_atomic(&mut self, state: &SetupState) -> Result<(), SetupError>;
    fn snapshot(&mut self, generation: &str) -> Result<BackupRecord, SetupError>;
    fn restore(&mut self, rollback: &RollbackPlan) -> Result<(), SetupError>;
    fn acquire_exclusive_lock(&mut self) -> Result<StateLock, SetupError>;
    fn release_exclusive_lock(&mut self, lock: StateLock) -> Result<(), SetupError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OnDiskSetupStore {
    root: PathBuf,
    state: PathBuf,
}

impl OnDiskSetupStore {
    pub fn open(platform_state_root: PathBuf) -> Result<Self, SetupError> {
        let root = validate_root(platform_state_root)?;
        let marker = root.join(".legion-owned");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(err(
                    SetupErrorCode::PathEscapeRefused,
                    "state ownership marker is a symlink",
                ));
            }
            Ok(metadata) if metadata.is_file() => {
                if read(&marker)? != OWNER_MARKER.as_bytes() {
                    return Err(err(
                        SetupErrorCode::PurgeOwnershipUnproven,
                        "state root ownership marker is invalid",
                    ));
                }
            }
            Ok(_) => {
                return Err(err(
                    SetupErrorCode::PurgeOwnershipUnproven,
                    "state ownership marker is not a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_write(&root, &marker, OWNER_MARKER.as_bytes())?;
            }
            Err(error) => return Err(io(error)),
        }
        for name in ["snapshots", "journal", "locks", "leases", "integrations"] {
            let directory = root.join(name);
            fs::create_dir_all(&directory).map_err(io)?;
            let metadata = fs::symlink_metadata(&directory).map_err(io)?;
            if metadata.file_type().is_symlink() {
                return Err(err(
                    SetupErrorCode::PathEscapeRefused,
                    format!("state directory {name} is a symlink"),
                ));
            }
            if !metadata.is_dir() {
                return Err(err(
                    SetupErrorCode::PlatformStateRootInvalid,
                    format!("state directory {name} is not a directory"),
                ));
            }
        }
        Ok(Self {
            state: root.join("setup-state.json"),
            root,
        })
    }
    pub fn state_path(&self) -> &Path {
        &self.state
    }
}

impl SetupStore for OnDiskSetupStore {
    fn platform_state_root(&self) -> &Path {
        &self.root
    }
    fn load_state(&self) -> Result<Option<SetupState>, SetupError> {
        require_contained(&self.root, &self.state)?;
        if !self.state.exists() {
            return Ok(None);
        }
        let state = serde_json::from_slice(&read(&self.state)?).map_err(|_| {
            err(
                SetupErrorCode::StateMetadataInvalid,
                "setup state is corrupt; run legion setup --repair",
            )
        })?;
        Ok(Some(state))
    }
    fn write_state_atomic(&mut self, state: &SetupState) -> Result<(), SetupError> {
        if state.schema_version != SETUP_REGISTRY_SCHEMA_VERSION
            || state.migration_generation.trim().is_empty()
        {
            return Err(err(
                SetupErrorCode::StateMetadataInvalid,
                "state metadata is incomplete",
            ));
        }
        let bytes = serde_json::to_vec(state).map_err(|_| {
            err(
                SetupErrorCode::StateSerializationFailed,
                "cannot encode setup state",
            )
        })?;
        atomic_write(&self.root, &self.state, &bytes)
    }
    fn snapshot(&mut self, generation: &str) -> Result<BackupRecord, SetupError> {
        require_contained(&self.root, &self.state)?;
        let snapshot = self
            .root
            .join("snapshots")
            .join(format!("{generation}.json"));
        let bytes = if self.state.exists() {
            read(&self.state)?
        } else {
            b"null".to_vec()
        };
        require_contained(&self.root, &snapshot)?;
        if snapshot.exists() {
            if fs::symlink_metadata(&snapshot)
                .map_err(io)?
                .file_type()
                .is_symlink()
            {
                return Err(err(
                    SetupErrorCode::PathEscapeRefused,
                    "snapshot path is a symlink",
                ));
            }
            if read(&snapshot)? != bytes {
                return Err(err(
                    SetupErrorCode::SnapshotFailed,
                    "immutable snapshot generation does not match the current state",
                ));
            }
        } else {
            atomic_write(&self.root, &snapshot, &bytes)?;
        }
        Ok(BackupRecord {
            target: self.state.clone(),
            snapshot,
            digest: digest_bytes(&bytes),
        })
    }
    fn restore(&mut self, rollback: &RollbackPlan) -> Result<(), SetupError> {
        require_contained(&self.root, &rollback.snapshot)?;
        let bytes = read(&rollback.snapshot).map_err(|_| {
            err(
                SetupErrorCode::SnapshotFailed,
                "rollback snapshot cannot be read",
            )
        })?;
        if bytes == b"null" {
            if self.state.exists() {
                fs::remove_file(&self.state).map_err(io)?;
            }
        } else {
            let _: SetupState = serde_json::from_slice(&bytes).map_err(|_| {
                err(
                    SetupErrorCode::SnapshotFailed,
                    "rollback snapshot is corrupt",
                )
            })?;
            atomic_write(&self.root, &self.state, &bytes)?;
        }
        Ok(())
    }
    fn acquire_exclusive_lock(&mut self) -> Result<StateLock, SetupError> {
        let path = self.root.join("locks/lifecycle.lock");
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(b"legion setup lifecycle lock").map_err(io)?;
                file.sync_all().map_err(io)?;
                Ok(StateLock { lock_path: path })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(err(
                SetupErrorCode::StateLockUnavailable,
                "another setup lifecycle operation holds the exclusive lock",
            )),
            Err(error) => Err(io(error)),
        }
    }
    fn release_exclusive_lock(&mut self, lock: StateLock) -> Result<(), SetupError> {
        let expected = self.root.join("locks/lifecycle.lock");
        if lock.lock_path != expected {
            return Err(err(
                SetupErrorCode::StateLockUnavailable,
                "lock does not belong to this state root",
            ));
        }
        fs::remove_file(expected).map_err(io)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    rollback: RollbackPlan,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningReceipt {
    schema_version: u32,
    kind: String,
    release_version: String,
    runtime_sha256: String,
    signer: String,
    authenticode_status: String,
    timestamped: bool,
    rightkit_ax_version: String,
    rightkit_ax_source_commit: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PurgeReceipt {
    purged: Vec<PathBuf>,
    retained: Vec<PathBuf>,
    ownership_proof: String,
}

pub struct SetupRegistry<S: SetupStore> {
    store: S,
    release: BoundRelease,
    clients: BTreeMap<String, ClientStatus>,
}

impl<S: SetupStore> SetupRegistry<S> {
    pub fn open(store: S, release: BoundRelease) -> Result<Self, SetupError> {
        validate_release(&release)?;
        let clients = load_clients(store.platform_state_root())?;
        Ok(Self {
            store,
            release,
            clients,
        })
    }
    pub fn recover(&mut self) -> Result<RecoveryReport, SetupError> {
        let path = journal_path(self.store.platform_state_root());
        if !path.exists() {
            return Ok(RecoveryReport {
                recovered_generation: None,
                remediation: Vec::new(),
            });
        }
        let journal: Journal = serde_json::from_slice(&read(&path)?).map_err(|_| {
            err(
                SetupErrorCode::JournalIncomplete,
                "interrupted setup journal is invalid; run legion setup --repair",
            )
        })?;
        let lock = self.store.acquire_exclusive_lock()?;
        let result = self.store.restore(&journal.rollback).map_err(|_| {
            err(
                SetupErrorCode::RecoveryFailed,
                "cannot restore interrupted setup generation",
            )
        });
        let release = self.store.release_exclusive_lock(lock);
        result?;
        release?;
        fs::remove_file(path).map_err(io)?;
        Ok(RecoveryReport {
            recovered_generation: Some(journal.rollback.generation),
            remediation: vec!["restored last verified generation".into()],
        })
    }
    pub fn detect(
        &self,
        selector: &ClientSelector,
        evidence: &[ClientEvidence],
    ) -> Result<Vec<DetectedClient>, SetupError> {
        let mut result = evidence
            .iter()
            .filter(|item| matches_selector(selector, &item.client_id))
            .map(detected)
            .collect::<Vec<_>>();
        result.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        if let ClientSelector::ClientId(id) = selector {
            if result.is_empty() || result[0].fidelity == "Unavailable" {
                return Err(err(
                    SetupErrorCode::ClientNotDetected,
                    format!("supported client {id} was not detected"),
                ));
            }
        }
        Ok(result)
    }
    pub fn status(&self, selector: &ClientSelector) -> Result<Vec<ClientStatus>, SetupError> {
        let mut values = self
            .clients
            .values()
            .filter(|item| matches_selector(selector, &item.client_id))
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(values)
    }
    pub fn preview(&mut self, request: SetupRequest) -> Result<SetupPreview, SetupError> {
        validate_release(&request.release)?;
        same_root(
            self.store.platform_state_root(),
            &request.platform_state_root,
        )?;
        if request.release != self.release {
            return Err(err(
                SetupErrorCode::ReleaseBindingMismatch,
                "setup request release differs from verified native release",
            ));
        }
        let clients = self.detect(&request.selector, &request.client_evidence)?;
        if matches!(
            request.action,
            SetupAction::Apply | SetupAction::Repair | SetupAction::Disable | SetupAction::Remove
        ) && clients.is_empty()
        {
            return Err(err(
                SetupErrorCode::ClientNotDetected,
                "no selected supported client was detected",
            ));
        }
        let state = self.store.load_state()?;
        let generation = state
            .as_ref()
            .map(|s| s.migration_generation.clone())
            .unwrap_or_else(|| "0".into());
        let mutations = clients
            .iter()
            .map(|client| {
                let operation = format!("{:?}", request.action).to_lowercase();
                let target = self
                    .store
                    .platform_state_root()
                    .join("integrations")
                    .join(format!("{}.json", client.client_id));
                let digest = digest_bytes(
                    format!(
                        "{}:{}:{}",
                        client.client_id, operation, request.release.release_version
                    )
                    .as_bytes(),
                );
                PlannedMutation {
                    target,
                    operation,
                    digest,
                }
            })
            .collect::<Vec<_>>();
        let snapshot = self
            .store
            .platform_state_root()
            .join("snapshots")
            .join(format!("{generation}.json"));
        let prior = if self
            .store
            .platform_state_root()
            .join("setup-state.json")
            .exists()
        {
            digest_bytes(&read(
                &self.store.platform_state_root().join("setup-state.json"),
            )?)
        } else {
            "absent".into()
        };
        let backups = vec![BackupRecord {
            target: self.store.platform_state_root().join("setup-state.json"),
            snapshot: snapshot.clone(),
            digest: prior,
        }];
        let rollback = RollbackPlan {
            generation,
            snapshot,
            release: self.release.clone(),
        };
        let external_qualification =
            external_qualification(&clients, self.store.platform_state_root(), &request.release);
        let plan_digest = compute_plan_digest(
            &request,
            &clients,
            &mutations,
            &rollback,
            &external_qualification,
        )?;
        Ok(SetupPreview {
            plan_id: format!("setup-{plan_digest}"),
            plan_digest,
            request,
            clients,
            mutations,
            backups,
            rollback,
            external_qualification,
        })
    }
    pub fn confirm(
        &self,
        preview: SetupPreview,
        confirmation: PlanConfirmation,
    ) -> Result<ConfirmedSetup, SetupError> {
        let expected_digest = compute_plan_digest(
            &preview.request,
            &preview.clients,
            &preview.mutations,
            &preview.rollback,
            &preview.external_qualification,
        )?;
        if preview.plan_digest != expected_digest
            || preview.plan_id != format!("setup-{expected_digest}")
        {
            return Err(err(
                SetupErrorCode::PlanStale,
                "setup plan contents no longer match its recorded identity",
            ));
        }
        if preview.plan_id != confirmation.plan_id
            || preview.plan_digest != confirmation.plan_digest
        {
            return Err(err(
                SetupErrorCode::PlanConfirmationRequired,
                "confirmation must match the reviewed plan ID and digest",
            ));
        }
        if preview.request.dry_run
            || matches!(
                preview.request.action,
                SetupAction::Preview | SetupAction::Status
            )
        {
            return Err(err(
                SetupErrorCode::PlanConfirmationRequired,
                "dry-run and preview plans cannot execute",
            ));
        }
        Ok(ConfirmedSetup {
            preview,
            confirmation,
        })
    }
    pub fn execute(&mut self, confirmed: ConfirmedSetup) -> Result<SetupExecution, SetupError> {
        let confirmed = self.confirm(confirmed.preview, confirmed.confirmation)?;
        validate_release(&confirmed.preview.request.release)?;
        same_root(
            self.store.platform_state_root(),
            &confirmed.preview.request.platform_state_root,
        )?;
        if confirmed.preview.request.release != self.release {
            return Err(err(
                SetupErrorCode::ReleaseBindingMismatch,
                "setup request release differs from verified native release",
            ));
        }
        let lock = self.store.acquire_exclusive_lock()?;
        let prior_clients = self.clients.clone();
        let mut started = false;
        let operation = match self.store.load_state() {
            Ok(state)
                if state
                    .as_ref()
                    .map(|s| &s.migration_generation)
                    .unwrap_or(&"0".into())
                    != &confirmed.preview.rollback.generation =>
            {
                Err(err(
                    SetupErrorCode::PlanStale,
                    "setup state changed after preview",
                ))
            }
            Ok(_) => {
                started = true;
                self.execute_locked(&confirmed.preview)
            }
            Err(error) => Err(error),
        };
        let result = match operation {
            Ok(value) => Ok(value),
            Err(operation_error)
                if started && journal_path(self.store.platform_state_root()).exists() =>
            {
                self.clients = prior_clients;
                match self
                    .store
                    .restore(&confirmed.preview.rollback)
                    .and_then(|_| save_clients(self.store.platform_state_root(), &self.clients))
                {
                    Ok(()) => match fs::remove_file(journal_path(self.store.platform_state_root()))
                    {
                        Ok(()) => Err(operation_error),
                        Err(_) => Err(err(
                            SetupErrorCode::RollbackFailed,
                            "setup failure journal could not be cleared after rollback",
                        )),
                    },
                    Err(_) => Err(err(
                        SetupErrorCode::RollbackFailed,
                        "setup failure could not be compensated from the verified snapshot",
                    )),
                }
            }
            Err(operation_error) => Err(operation_error),
        };
        let unlock = self.store.release_exclusive_lock(lock);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(_), Err(_)) => Err(err(
                SetupErrorCode::RollbackFailed,
                "setup failed and lifecycle lock could not be released",
            )),
        }
    }
    pub fn rollback(&mut self, rollback: RollbackPlan) -> Result<SetupExecution, SetupError> {
        if active_leases(self.store.platform_state_root())? {
            return Err(err(
                SetupErrorCode::RuntimeLeaseActive,
                "old runtime leases must close before rollback",
            ));
        }
        let lock = self.store.acquire_exclusive_lock()?;
        let result = self.store.restore(&rollback).and_then(|_| {
            self.store.write_state_atomic(&SetupState {
                schema_version: SETUP_REGISTRY_SCHEMA_VERSION,
                migration_generation: rollback.generation.clone(),
            })
        });
        let unlock = self.store.release_exclusive_lock(lock);
        result.map_err(|_| {
            err(
                SetupErrorCode::RollbackFailed,
                "rollback could not restore the verified snapshot",
            )
        })?;
        unlock?;
        let rollback_release = rollback.release.clone();
        self.release = rollback_release.clone();
        Ok(SetupExecution {
            action: SetupAction::Repair,
            generation: Some(rollback.generation),
            clients: self.status(&ClientSelector::AllSupported)?,
            remediation: Vec::new(),
            external_qualification: external_qualification(
                &[],
                self.store.platform_state_root(),
                &rollback_release,
            ),
            purged: Vec::new(),
            retained: Vec::new(),
            ownership_proof: None,
        })
    }
    pub fn acquire_runtime_lease(
        &mut self,
        client_id: String,
        generation: String,
    ) -> Result<RuntimeLease, SetupError> {
        let current = self
            .store
            .load_state()?
            .map(|s| s.migration_generation)
            .unwrap_or_else(|| "0".into());
        if generation != current {
            return Err(err(
                SetupErrorCode::RuntimeLeaseActive,
                "runtime lease generation is not active",
            ));
        }
        let lease = RuntimeLease {
            lease_id: format!("{}-{}", client_id, nonce()),
            client_id,
            generation,
        };
        let path = self
            .store
            .platform_state_root()
            .join("leases")
            .join(format!("{}.json", lease.lease_id));
        let bytes = serde_json::to_vec(&lease).map_err(|_| {
            err(
                SetupErrorCode::StateSerializationFailed,
                "cannot encode runtime lease",
            )
        })?;
        write_new(&path, &bytes)?;
        Ok(lease)
    }
    pub fn release_runtime_lease(&mut self, lease: RuntimeLease) -> Result<(), SetupError> {
        let path = self
            .store
            .platform_state_root()
            .join("leases")
            .join(format!("{}.json", lease.lease_id));
        require_contained(self.store.platform_state_root(), &path)?;
        let found: RuntimeLease = serde_json::from_slice(&read(&path)?).map_err(|_| {
            err(
                SetupErrorCode::StateMetadataInvalid,
                "runtime lease is corrupt",
            )
        })?;
        if found != lease {
            return Err(err(
                SetupErrorCode::ConfigOwnershipConflict,
                "runtime lease ownership does not match",
            ));
        }
        fs::remove_file(path).map_err(io)
    }
    fn execute_locked(&mut self, preview: &SetupPreview) -> Result<SetupExecution, SetupError> {
        if matches!(
            preview.request.action,
            SetupAction::Apply | SetupAction::Repair | SetupAction::Remove | SetupAction::Purge
        ) && active_leases(self.store.platform_state_root())?
        {
            return Err(err(
                SetupErrorCode::RuntimeLeaseActive,
                "active client runtime leases block lifecycle mutation",
            ));
        }
        write_journal(
            self.store.platform_state_root(),
            &Journal {
                rollback: preview.rollback.clone(),
            },
        )?;
        self.store.snapshot(&preview.rollback.generation)?;
        let next = next_generation(&preview.rollback.generation);
        self.store.write_state_atomic(&SetupState {
            schema_version: SETUP_REGISTRY_SCHEMA_VERSION,
            migration_generation: next.clone(),
        })?;
        for detected in &preview.clients {
            let status = match preview.request.action {
                SetupAction::Disable => ClientStatus {
                    client_id: detected.client_id.clone(),
                    installed: true,
                    fidelity: "Disabled".into(),
                    bound_release: Some(self.release.clone()),
                    missing_surfaces: detected.missing_surfaces.clone(),
                    remediation: vec!["run legion setup repair to re-enable".into()],
                },
                SetupAction::Remove | SetupAction::Purge => ClientStatus {
                    client_id: detected.client_id.clone(),
                    installed: false,
                    fidelity: "Unavailable".into(),
                    bound_release: None,
                    missing_surfaces: vec!["integration removed".into()],
                    remediation: Vec::new(),
                },
                _ => ClientStatus {
                    client_id: detected.client_id.clone(),
                    installed: true,
                    fidelity: detected.fidelity.clone(),
                    bound_release: Some(self.release.clone()),
                    missing_surfaces: detected.missing_surfaces.clone(),
                    remediation: detected.remediation.clone(),
                },
            };
            self.clients.insert(status.client_id.clone(), status);
        }
        let purge_receipt = if matches!(preview.request.action, SetupAction::Purge) {
            let receipt = verified_purge(self.store.platform_state_root())?;
            self.clients.clear();
            Some(receipt)
        } else {
            save_clients(self.store.platform_state_root(), &self.clients)?;
            None
        };
        let journal = journal_path(self.store.platform_state_root());
        if journal.exists() {
            fs::remove_file(journal).map_err(io)?;
        }
        Ok(SetupExecution {
            action: preview.request.action.clone(),
            generation: Some(next),
            clients: self.status(&preview.request.selector)?,
            remediation: Vec::new(),
            external_qualification: preview.external_qualification.clone(),
            purged: purge_receipt
                .as_ref()
                .map(|receipt| receipt.purged.clone())
                .unwrap_or_default(),
            retained: purge_receipt
                .as_ref()
                .map(|receipt| receipt.retained.clone())
                .unwrap_or_default(),
            ownership_proof: purge_receipt.map(|receipt| receipt.ownership_proof),
        })
    }
}

impl SetupRegistry<OnDiskSetupStore> {
    /// Opens the sole canonical native platform-user-data root for product use.
    pub fn open_platform(release: BoundRelease) -> Result<Self, SetupError> {
        Self::open_on_disk(release, platform_state_root()?)
    }

    /// Low-level seam for host tests and already-verified integrations only.
    /// Product CLI entry points must use [`Self::open_platform`].
    pub fn open_on_disk(
        release: BoundRelease,
        platform_state_root: PathBuf,
    ) -> Result<Self, SetupError> {
        Self::open(OnDiskSetupStore::open(platform_state_root)?, release)
    }
}

/// Resolves the native platform-local data convention with the fixed Legion suffix.
pub fn platform_state_root() -> Result<PathBuf, SetupError> {
    let directories = directories_next::BaseDirs::new().ok_or_else(|| {
        err(
            SetupErrorCode::PlatformStateRootInvalid,
            "native platform user-data directory is unavailable",
        )
    })?;
    Ok(directories.data_local_dir().join("Legion"))
}

fn err(code: SetupErrorCode, remediation: impl Into<String>) -> SetupError {
    SetupError {
        code,
        remediation: remediation.into(),
    }
}
fn io(error: std::io::Error) -> SetupError {
    err(SetupErrorCode::StateSerializationFailed, error.to_string())
}
fn read(path: &Path) -> Result<Vec<u8>, SetupError> {
    fs::read(path).map_err(io)
}
fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
fn validate_release(release: &BoundRelease) -> Result<(), SetupError> {
    if [
        &release.release_version,
        &release.runtime_digest,
        &release.capability_catalog_hash,
        &release.mcp_tool_schema_hash,
        &release.declarative_asset_schema_hash,
        &release.state_compatibility,
    ]
    .iter()
    .any(|v| v.trim().is_empty())
    {
        Err(err(
            SetupErrorCode::ReleaseBindingMismatch,
            "release binding is incomplete; run legion setup --repair",
        ))
    } else {
        Ok(())
    }
}
fn matches_selector(selector: &ClientSelector, client: &str) -> bool {
    matches!(selector, ClientSelector::AllSupported)
        || matches!(selector, ClientSelector::ClientId(id) if id == client)
}
fn detected(evidence: &ClientEvidence) -> DetectedClient {
    let mut mechanisms = evidence.mechanisms.clone();
    mechanisms.sort();
    mechanisms.dedup();
    if !evidence.detected {
        return DetectedClient {
            client_id: evidence.client_id.clone(),
            selected_mechanism: String::new(),
            fidelity: "Unavailable".into(),
            missing_surfaces: vec!["client not detected".into()],
            remediation: vec!["install or select a supported client".into()],
        };
    }
    if mechanisms.is_empty() {
        return DetectedClient {
            client_id: evidence.client_id.clone(),
            selected_mechanism: String::new(),
            fidelity: "Unavailable".into(),
            missing_surfaces: vec!["supported mechanism".into()],
            remediation: vec!["configure a supported integration mechanism".into()],
        };
    }
    let mut missing = Vec::new();
    if evidence.command_proof_ref.is_none() {
        missing.push("command resolution proof".into());
    }
    if evidence.qualification_evidence_ref.is_none() {
        missing.push("real-client qualification evidence".into());
    }
    let qualified = missing.is_empty();
    DetectedClient {
        client_id: evidence.client_id.clone(),
        selected_mechanism: mechanisms.remove(0),
        fidelity: if qualified {
            "Full".into()
        } else {
            "Baseline".into()
        },
        missing_surfaces: missing,
        remediation: if qualified {
            Vec::new()
        } else {
            vec!["legion setup --repair".into()]
        },
    }
}
fn external_qualification(
    clients: &[DetectedClient],
    platform_state_root: &Path,
    release: &BoundRelease,
) -> ExternalQualification {
    let mut missing: Vec<String> = clients
        .iter()
        .filter(|client| client.fidelity != "Full")
        .map(|client| format!("qualified client evidence: {}", client.client_id))
        .collect();
    if clients.is_empty() {
        missing.push("qualified client evidence".into());
    }
    let (signed_platform, pinned_rightkit) = signing_receipt_evidence(platform_state_root, release);
    if !signed_platform {
        missing.push("signed native platform artifact".into());
    }
    if !pinned_rightkit {
        missing.push("pinned RightKit AX identity".into());
    }
    missing.sort();
    ExternalQualification {
        status: if missing.is_empty() {
            ExternalQualificationStatus::Qualified
        } else {
            ExternalQualificationStatus::ExternalQualificationBlocked
        },
        missing_evidence: missing,
    }
}

fn signing_receipt_evidence(platform_state_root: &Path, release: &BoundRelease) -> (bool, bool) {
    let path = platform_state_root.join(SIGNING_RECEIPT_RELATIVE_PATH);
    let receipt = fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SigningReceipt>(&bytes).ok());
    let Some(receipt) = receipt else {
        return (false, false);
    };
    let signed = receipt.schema_version == 1
        && receipt.kind == "legion-signing-receipt"
        && receipt.release_version == release.release_version
        && receipt.runtime_sha256 == release.runtime_digest
        && receipt.authenticode_status == "Valid"
        && receipt.timestamped
        && receipt.signer == "Damned Ventures LLC";
    let pinned = receipt.rightkit_ax_version == RIGHTKIT_AX_VERSION
        && receipt.rightkit_ax_source_commit == RIGHTKIT_AX_SOURCE_COMMIT;
    (signed, pinned)
}
fn compute_plan_digest(
    request: &SetupRequest,
    clients: &[DetectedClient],
    mutations: &[PlannedMutation],
    rollback: &RollbackPlan,
    external_qualification: &ExternalQualification,
) -> Result<String, SetupError> {
    let plan_material = serde_json::to_vec(&(
        request,
        clients,
        mutations,
        rollback,
        external_qualification,
    ))
    .map_err(|_| {
        err(
            SetupErrorCode::StateSerializationFailed,
            "cannot create setup plan",
        )
    })?;
    Ok(digest_bytes(&plan_material))
}
fn next_generation(generation: &str) -> String {
    generation
        .parse::<u64>()
        .map(|n| n.saturating_add(1).to_string())
        .unwrap_or_else(|_| format!("{}-next", generation))
}
fn same_root(expected: &Path, supplied: &Path) -> Result<(), SetupError> {
    let supplied = fs::canonicalize(supplied).map_err(|_| {
        err(
            SetupErrorCode::PlatformStateRootInvalid,
            "cannot resolve requested platform state root",
        )
    })?;
    if supplied != expected {
        Err(err(
            SetupErrorCode::PlatformStateRootInvalid,
            "requested state root is not the canonical Legion platform root",
        ))
    } else {
        Ok(())
    }
}
fn validate_root(root: PathBuf) -> Result<PathBuf, SetupError> {
    if !root.is_absolute() || root.components().any(|c| {
        matches!(c, Component::ParentDir)
            || matches!(c, Component::Normal(name) if name == ".audit" || name == "node_modules")
    }) {
        return Err(err(
            SetupErrorCode::PlatformStateRootInvalid,
            "canonical Legion state root must be an absolute non-project path",
        ));
    }
    let mut lexical_component = PathBuf::new();
    for component in root.components() {
        lexical_component.push(component.as_os_str());
        match fs::symlink_metadata(&lexical_component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(err(
                    SetupErrorCode::PathEscapeRefused,
                    "state root traverses a symlink",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(io(error)),
        }
    }
    fs::create_dir_all(&root).map_err(io)?;
    let canonical = fs::canonicalize(&root).map_err(io)?;
    for ancestor in canonical.ancestors() {
        if fs::symlink_metadata(ancestor)
            .map_err(io)?
            .file_type()
            .is_symlink()
        {
            return Err(err(
                SetupErrorCode::PathEscapeRefused,
                "state root traverses a symlink",
            ));
        }
        if ancestor.join(".git").exists()
            && (ancestor.join("Cargo.toml").exists() || ancestor.join("package.json").exists())
        {
            return Err(err(
                SetupErrorCode::SourceCheckoutReferenceRefused,
                "canonical state root may not reside in a source checkout",
            ));
        }
    }
    Ok(canonical)
}
fn require_contained(root: &Path, path: &Path) -> Result<(), SetupError> {
    if !path.starts_with(root) {
        return Err(err(
            SetupErrorCode::PathEscapeRefused,
            "state path escapes the canonical root",
        ));
    }
    for ancestor in path.ancestors().take_while(|p| p.starts_with(root)) {
        if ancestor.exists()
            && fs::symlink_metadata(ancestor)
                .map_err(io)?
                .file_type()
                .is_symlink()
        {
            return Err(err(
                SetupErrorCode::PathEscapeRefused,
                "state path traverses a symlink",
            ));
        }
    }
    Ok(())
}
fn atomic_write(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), SetupError> {
    require_contained(root, path)?;
    let parent = path.parent().ok_or_else(|| {
        err(
            SetupErrorCode::PathEscapeRefused,
            "state path has no parent",
        )
    })?;
    fs::create_dir_all(parent).map_err(io)?;
    let temporary = parent.join(format!(".tmp-{}", nonce()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io)?;
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
    }
    fs::rename(temporary, path).map_err(io)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), SetupError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                err(
                    SetupErrorCode::StateLockUnavailable,
                    "duplicate runtime lease",
                )
            } else {
                io(error)
            }
        })?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)
}
fn journal_path(root: &Path) -> PathBuf {
    root.join("journal/pending.json")
}
fn write_journal(root: &Path, journal: &Journal) -> Result<(), SetupError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| {
        err(
            SetupErrorCode::StateSerializationFailed,
            "cannot encode migration journal",
        )
    })?;
    atomic_write(root, &journal_path(root), &bytes)
}
fn clients_path(root: &Path) -> PathBuf {
    root.join("integrations/clients.json")
}
fn load_clients(root: &Path) -> Result<BTreeMap<String, ClientStatus>, SetupError> {
    let path = clients_path(root);
    require_contained(root, &path)?;
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_slice(&read(&path)?).map_err(|_| {
        err(
            SetupErrorCode::StateMetadataInvalid,
            "client registry is corrupt",
        )
    })
}
fn save_clients(root: &Path, clients: &BTreeMap<String, ClientStatus>) -> Result<(), SetupError> {
    let bytes = serde_json::to_vec(clients).map_err(|_| {
        err(
            SetupErrorCode::StateSerializationFailed,
            "cannot encode client registry",
        )
    })?;
    atomic_write(root, &clients_path(root), &bytes)
}
fn active_leases(root: &Path) -> Result<bool, SetupError> {
    let directory = root.join("leases");
    Ok(fs::read_dir(directory)
        .map_err(io)?
        .next()
        .transpose()
        .map_err(io)?
        .is_some())
}
fn verified_purge(root: &Path) -> Result<PurgeReceipt, SetupError> {
    let marker = root.join(".legion-owned");
    let marker_metadata = match fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(err(
                SetupErrorCode::PurgeOwnershipUnproven,
                "state ownership marker is missing",
            ));
        }
        Err(error) => return Err(io(error)),
    };
    if marker_metadata.file_type().is_symlink() {
        return Err(err(
            SetupErrorCode::PathEscapeRefused,
            "state ownership marker is a symlink",
        ));
    }
    let marker_bytes = read(&marker)?;
    if marker_bytes != OWNER_MARKER.as_bytes() {
        return Err(err(
            SetupErrorCode::PurgeOwnershipUnproven,
            "state root ownership is not proven",
        ));
    }
    validate_owned_tree(root)?;
    let mut purged = Vec::new();
    let mut retained = Vec::new();
    for entry in fs::read_dir(root).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !matches!(
            name.as_ref(),
            ".legion-owned"
                | "setup-state.json"
                | "snapshots"
                | "journal"
                | "leases"
                | "integrations"
                | "locks"
        ) {
            return Err(err(
                SetupErrorCode::PurgeOwnershipUnproven,
                format!("unrecognized state-root entry {name}"),
            ));
        }
        if fs::symlink_metadata(entry.path())
            .map_err(io)?
            .file_type()
            .is_symlink()
        {
            return Err(err(
                SetupErrorCode::PathEscapeRefused,
                "purge refuses symlinked state entries",
            ));
        }
        let path = entry.path();
        if name == ".legion-owned" || name == "locks" {
            retained.push(path);
        } else {
            purged.push(path);
        }
    }
    purged.sort();
    retained.sort();
    for path in &purged {
        if path.is_dir() {
            fs::remove_dir_all(path).map_err(io)?;
        } else {
            fs::remove_file(path).map_err(io)?;
        }
    }
    Ok(PurgeReceipt {
        purged,
        retained,
        ownership_proof: format!(
            "marker:{}:{}",
            marker.display(),
            digest_bytes(&marker_bytes)
        ),
    })
}

fn validate_owned_tree(root: &Path) -> Result<(), SetupError> {
    for entry in fs::read_dir(root).map_err(io)? {
        let entry = entry.map_err(io)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(io)?;
        if metadata.file_type().is_symlink() {
            return Err(err(
                SetupErrorCode::PathEscapeRefused,
                "purge refuses symlinked state entries",
            ));
        }
        require_contained(root, &path)?;
        if metadata.is_dir() {
            validate_owned_tree(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new(label: &str) -> Self {
            Self(std::env::temp_dir().join(format!("legion-host-{label}-{}", nonce())))
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn release() -> BoundRelease {
        BoundRelease {
            release_version: "0.1.0".into(),
            runtime_digest: "runtime".into(),
            capability_catalog_hash: "catalog".into(),
            mcp_tool_schema_hash: "schema".into(),
            declarative_asset_schema_hash: "assets".into(),
            state_compatibility: "1".into(),
        }
    }
    fn request(root: PathBuf, action: SetupAction) -> SetupRequest {
        SetupRequest {
            action,
            selector: ClientSelector::ClientId("claude-code".into()),
            release: release(),
            platform_state_root: root,
            dry_run: false,
            client_evidence: vec![ClientEvidence {
                client_id: "claude-code".into(),
                detected: true,
                mechanisms: vec!["agent-plugins-bare-command".into()],
                command_proof_ref: Some("proof".into()),
                qualification_evidence_ref: None,
            }],
        }
    }

    #[test]
    fn preview_is_non_mutating_and_execution_requires_matching_confirmation() {
        let root = TestRoot::new("preview");
        let mut registry = SetupRegistry::open_on_disk(release(), root.0.clone()).unwrap();
        let preview = registry
            .preview(request(root.0.clone(), SetupAction::Apply))
            .unwrap();
        assert!(registry.store.load_state().unwrap().is_none());
        assert_eq!(
            preview.external_qualification.status,
            ExternalQualificationStatus::ExternalQualificationBlocked
        );
        let wrong = PlanConfirmation {
            plan_id: "wrong".into(),
            plan_digest: preview.plan_digest.clone(),
        };
        assert_eq!(
            registry.confirm(preview.clone(), wrong).unwrap_err().code,
            SetupErrorCode::PlanConfirmationRequired
        );
        let confirmation = PlanConfirmation {
            plan_id: preview.plan_id.clone(),
            plan_digest: preview.plan_digest.clone(),
        };
        let result = registry
            .execute(registry.confirm(preview, confirmation).unwrap())
            .unwrap();
        assert_eq!(result.generation.as_deref(), Some("1"));
        assert!(registry.status(&ClientSelector::AllSupported).unwrap()[0].installed);
    }

    #[test]
    fn leases_block_mutation_and_verified_purge_refuses_foreign_entries() {
        let root = TestRoot::new("lease");
        let mut registry = SetupRegistry::open_on_disk(release(), root.0.clone()).unwrap();
        let preview = registry
            .preview(request(root.0.clone(), SetupAction::Apply))
            .unwrap();
        let confirmed = registry
            .confirm(
                preview.clone(),
                PlanConfirmation {
                    plan_id: preview.plan_id.clone(),
                    plan_digest: preview.plan_digest.clone(),
                },
            )
            .unwrap();
        registry.execute(confirmed).unwrap();
        let lease = registry
            .acquire_runtime_lease("claude-code".into(), "1".into())
            .unwrap();
        let repair = registry
            .preview(request(root.0.clone(), SetupAction::Repair))
            .unwrap();
        let repair = registry
            .confirm(
                repair.clone(),
                PlanConfirmation {
                    plan_id: repair.plan_id.clone(),
                    plan_digest: repair.plan_digest.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            registry.execute(repair).unwrap_err().code,
            SetupErrorCode::RuntimeLeaseActive
        );
        registry.release_runtime_lease(lease).unwrap();
        let before_state = registry.store.load_state().unwrap();
        let before_clients = registry.status(&ClientSelector::AllSupported).unwrap();
        fs::write(root.0.join("foreign.txt"), "foreign").unwrap();
        let purge = registry
            .preview(request(root.0.clone(), SetupAction::Purge))
            .unwrap();
        let purge = registry
            .confirm(
                purge.clone(),
                PlanConfirmation {
                    plan_id: purge.plan_id.clone(),
                    plan_digest: purge.plan_digest.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            registry.execute(purge).unwrap_err().code,
            SetupErrorCode::PurgeOwnershipUnproven
        );
        assert_eq!(registry.store.load_state().unwrap(), before_state);
        assert_eq!(
            registry.status(&ClientSelector::AllSupported).unwrap(),
            before_clients
        );
        assert_eq!(registry.recover().unwrap().recovered_generation, None);
    }

    #[test]
    fn verified_purge_returns_deleted_and_preserved_roots() {
        let root = TestRoot::new("purge-receipt");
        let mut registry = SetupRegistry::open_on_disk(release(), root.0.clone()).unwrap();
        let canonical_root = fs::canonicalize(&root.0).unwrap();
        let preview = registry
            .preview(request(root.0.clone(), SetupAction::Purge))
            .unwrap();
        let result = registry
            .execute(
                registry
                    .confirm(
                        preview.clone(),
                        PlanConfirmation {
                            plan_id: preview.plan_id.clone(),
                            plan_digest: preview.plan_digest.clone(),
                        },
                    )
                    .unwrap(),
            )
            .unwrap();
        assert!(result
            .purged
            .iter()
            .any(|path| path == &canonical_root.join("snapshots")));
        assert!(result
            .retained
            .iter()
            .any(|path| path == &canonical_root.join(".legion-owned")));
        assert!(result
            .retained
            .iter()
            .any(|path| path == &canonical_root.join("locks")));
        assert!(result
            .ownership_proof
            .as_deref()
            .is_some_and(|proof| proof.starts_with("marker:")));
    }

    #[cfg(unix)]
    #[test]
    fn lexical_root_symlink_is_refused_before_canonicalization() {
        let root = TestRoot::new("lexical-symlink");
        let destination = root.0.join("destination");
        let lexical_link = root.0.join("link");
        fs::create_dir_all(&destination).unwrap();
        std::os::unix::fs::symlink(&destination, &lexical_link).unwrap();

        let error = OnDiskSetupStore::open(lexical_link.join("state")).unwrap_err();
        assert_eq!(error.code, SetupErrorCode::PathEscapeRefused);
        assert!(!destination.join("state").exists());
    }

    #[test]
    fn platform_state_root_is_native_user_data_with_legion_suffix() {
        let root = platform_state_root().unwrap();
        let native_data = directories_next::BaseDirs::new()
            .unwrap()
            .data_local_dir()
            .join("Legion");
        assert_eq!(root, native_data);
        assert!(root.is_absolute());
    }
}
