# M3 install, setup, and state lifecycle — parallel execution request

Execute H and C only from source revision `ee587d0f6d1e7f56c4889d8bdff578880b598315` after the
accepted M2 plugin-root correction. Execute T only from the integrated convergence baseline
`1f4092f059f1fc9f09446ab4f3c06ff9574f0c07`. The sole active implementation union is the nine paths in
`migration/native-rust/dispatches/M2-M7-OWNERSHIP-AMENDMENT.json#milestones.M3.activeTouchAllowlist`.
Legacy Node/Python decision and state tooling remains retained development/project tooling and is
read-only; no Membrane path is in scope.

**Authority packet path:** /workspace/scratch/fbc2585fc7a4/legion/migration/native-rust/dispatches/M3-DISPATCH.json

**Receipt path:** /workspace/scratch/fbc2585fc7a4/legion/migration/native-rust/dispatches/M3-DISPATCH.receipt.json

The integration owner is the only owner of primary-checkout HEAD, index, commit, push, and final
cross-lane verification. Workers use isolated worktrees and do not commit or push.

## Frozen cross-lane API

Before either implementation lane edits source, both consume this frozen public API in
`legion_host::setup_registry`; no lane may change it after the first lane begins. All listed public
models derive `Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize`; `PathBuf` fields
serialize as paths, and IDs/digests are owned `String`s.

```rust
pub const SETUP_REGISTRY_SCHEMA_VERSION: u32 = 1;

pub struct BoundRelease {
    pub release_version: String,
    pub runtime_digest: String,
    pub capability_catalog_hash: String,
    pub mcp_tool_schema_hash: String,
    pub declarative_asset_schema_hash: String,
    pub state_compatibility: String,
}
pub enum SetupAction { Preview, Apply, Status, Repair, Disable, Remove, Purge }
pub enum ClientSelector { AllSupported, ClientId(String) }
pub struct ClientEvidence {
    pub client_id: String,
    pub detected: bool,
    pub mechanisms: Vec<String>,
    pub command_proof_ref: Option<String>,
    pub qualification_evidence_ref: Option<String>,
}
pub struct SetupRequest {
    pub action: SetupAction,
    pub selector: ClientSelector,
    pub release: BoundRelease,
    pub platform_state_root: PathBuf,
    pub client_evidence: Vec<ClientEvidence>,
    pub dry_run: bool,
}
pub struct DetectedClient {
    pub client_id: String,
    pub selected_mechanism: String,
    pub fidelity: String,
    pub missing_surfaces: Vec<String>,
    pub remediation: Vec<String>,
}
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
pub struct PlanConfirmation { pub plan_id: String, pub plan_digest: String }
pub struct ConfirmedSetup { pub preview: SetupPreview, pub confirmation: PlanConfirmation }
pub struct ClientStatus {
    pub client_id: String,
    pub installed: bool,
    pub fidelity: String,
    pub bound_release: Option<BoundRelease>,
    pub missing_surfaces: Vec<String>,
    pub remediation: Vec<String>,
}
pub struct PlannedMutation { pub target: PathBuf, pub operation: String, pub digest: String }
pub struct BackupRecord { pub target: PathBuf, pub snapshot: PathBuf, pub digest: String }
pub struct RollbackPlan { pub generation: String, pub snapshot: PathBuf, pub release: BoundRelease }
pub struct SetupExecution {
    pub action: SetupAction,
    pub generation: Option<String>,
    pub clients: Vec<ClientStatus>,
    pub remediation: Vec<String>,
    pub external_qualification: ExternalQualification,
}
pub struct RecoveryReport { pub recovered_generation: Option<String>, pub remediation: Vec<String> }
pub struct RuntimeLease { pub lease_id: String, pub client_id: String, pub generation: String }
pub struct StateLock { pub lock_path: PathBuf }
pub struct SetupState { pub schema_version: u32, pub migration_generation: String }
pub struct ExternalQualification { pub status: ExternalQualificationStatus, pub missing_evidence: Vec<String> }
pub enum ExternalQualificationStatus { Qualified, ExternalQualificationBlocked }

pub trait SetupStore {
    fn platform_state_root(&self) -> &Path;
    fn load_state(&self) -> Result<Option<SetupState>, SetupError>;
    fn write_state_atomic(&mut self, state: &SetupState) -> Result<(), SetupError>;
    fn snapshot(&mut self, generation: &str) -> Result<BackupRecord, SetupError>;
    fn restore(&mut self, rollback: &RollbackPlan) -> Result<(), SetupError>;
    fn acquire_exclusive_lock(&mut self) -> Result<StateLock, SetupError>;
    fn release_exclusive_lock(&mut self, lock: StateLock) -> Result<(), SetupError>;
}
pub struct OnDiskSetupStore { /* private fields */ }
impl OnDiskSetupStore {
    pub fn open(platform_state_root: PathBuf) -> Result<Self, SetupError>;
    pub fn state_path(&self) -> &Path;
}
pub fn platform_state_root() -> Result<PathBuf, SetupError>;
pub struct SetupRegistry<S: SetupStore> { /* private fields */ }
impl<S: SetupStore> SetupRegistry<S> {
    pub fn open(store: S, release: BoundRelease) -> Result<Self, SetupError>;
    pub fn recover(&mut self) -> Result<RecoveryReport, SetupError>;
    pub fn detect(&self, selector: &ClientSelector, evidence: &[ClientEvidence])
        -> Result<Vec<DetectedClient>, SetupError>;
    pub fn status(&self, selector: &ClientSelector) -> Result<Vec<ClientStatus>, SetupError>;
    pub fn preview(&mut self, request: SetupRequest) -> Result<SetupPreview, SetupError>;
    pub fn confirm(&self, preview: SetupPreview, confirmation: PlanConfirmation)
        -> Result<ConfirmedSetup, SetupError>;
    pub fn execute(&mut self, confirmed: ConfirmedSetup) -> Result<SetupExecution, SetupError>;
    pub fn rollback(&mut self, rollback: RollbackPlan) -> Result<SetupExecution, SetupError>;
    pub fn acquire_runtime_lease(&mut self, client_id: String, generation: String)
        -> Result<RuntimeLease, SetupError>;
    pub fn release_runtime_lease(&mut self, lease: RuntimeLease) -> Result<(), SetupError>;
}
impl SetupRegistry<OnDiskSetupStore> {
    pub fn open_platform(release: BoundRelease) -> Result<Self, SetupError>;
    pub fn open_on_disk(release: BoundRelease, platform_state_root: PathBuf)
        -> Result<Self, SetupError>;
}
pub enum SetupErrorCode {
    ClientNotDetected, ClientMechanismUnsupported, PlanConfirmationRequired, PlanStale,
    ConfigOwnershipConflict, ConfigParseRefused, PathEscapeRefused,
    SourceCheckoutReferenceRefused, CommandResolutionFailed, ReleaseBindingMismatch,
    VerificationFailed, RollbackFailed, PurgeOwnershipUnproven, PlatformStateRootInvalid,
    StateMetadataInvalid, StateSerializationFailed, StateLockUnavailable, RuntimeLeaseActive,
    SnapshotFailed, JournalIncomplete, RecoveryFailed, ExternalQualificationBlocked,
}
pub struct SetupError { pub code: SetupErrorCode, pub remediation: String }
```

`platform_state_root` derives only `directories_next::BaseDirs::data_local_dir()/Legion`, the native
platform user-data convention; it never accepts or derives a temporary, source-checkout, project,
plugin, or client path. `open_platform` is the CLI's sole product constructor: C supplies only the
parsed `BoundRelease` and never accepts a caller state-root argument. `open_on_disk` remains a
low-level/test seam for H tests and already-verified integrations. C serializes and deserializes
`SetupRequest`, `SetupPreview`, `PlanConfirmation`, `ConfirmedSetup`, and
`ClientStatus` through their frozen serde derives. `preview` is non-mutating; only `execute` takes
`ConfirmedSetup`, whose confirmation must match both `plan_id` and `plan_digest`; `Apply` therefore
cannot mutate from a bare request. `recover`, `rollback`, and purge actions fail closed until the
store validates canonical-root ownership, lock/lease, snapshot/journal, release binding, and exact
Legion-owned targets.

The host-state lane may add private helpers but may not change public names, fields, operation
meaning, signatures, serialization, or typed failure mapping. The CLI lane may compile against
only this API.

## Parallel lanes and interface locks

Run H and C concurrently after reading this API lock:

- **H — host-state:** owns `engine/Cargo.lock`, `engine/crates/legion-host/Cargo.toml`,
  `engine/crates/legion-host/src/lib.rs`, and
  `engine/crates/legion-host/src/setup_registry.rs`. It implements the frozen state registry,
  platform-root containment, exclusive lifecycle lock, runtime leases, immutable snapshot/journal,
  transactional activation/rollback/recovery, and verified purge. It owns the direct
  `directories-next` native-platform resolver dependency and the resulting Cargo.lock resolution.
- **C — CLI grammar:** owns `engine/bins/legion/src/cli.rs`,
  `engine/bins/legion/src/commands/mod.rs`, and
  `engine/bins/legion/src/commands/setup.rs`. It adds only `legion setup` grammar/dispatch and
  bare `setup status` integration through the frozen host API. It must preserve M2's exact existing
  `legion serve --stdio --plugin-root ${PLUGIN_ROOT}` parse, containment, release-binding, and MCP
  startup behavior byte-for-contract; it may not reinterpret Serve, MCP, or `status --config`.
- **T — convergence:** owns `engine/crates/legion-testkit/Cargo.toml` and
  `engine/tests/m3_setup_state.rs`, and begins only after H and C are integrated at
  `1f4092f059f1fc9f09446ab4f3c06ff9574f0c07`. It registers the exact standalone test target and
  proves setup preview/confirmation, lifecycle mutations, state lock/lease, snapshot
  migration/rollback/recovery, ownership-safe purge, and the untouched plugin-root Serve contract.

## Required behavior

`legion setup` must detect supported clients, display fidelity, preview non-mutating changes,
require a plan-bound confirmation before mutation, stage backups, install/verify/repair/disable/
remove selected Legion-owned integrations, preserve unrelated configuration, and refuse unsafe
paths, source-checkout state, foreign configuration, stale plans, binding mismatch, and unproven
purge ownership. No operation starts an idle daemon or machine-wide socket. State uses only the
platform Legion user-data root and never `.audit`, plugin data, a source checkout, Membrane,
Cortex, or project workflow artifacts as canonical product state.

Repository-local code and tests may reach `EXTERNAL_QUALIFICATION_BLOCKED` when signed macOS or
Windows artifacts, Homebrew/WinGet installation, RightKit AX, or actual client environments are
absent. That typed state is honest source implementation evidence, not M3/M6 acceptance. M6 alone
owns immutable signed-artifact, Mac/Windows/Homebrew/WinGet, two-real-client, and Full-fidelity
qualification; no worker may fabricate PASS, publication, or release claims.

Run the exact owned focused checks plus integrated `cargo fmt --check`, `cargo check --locked`,
`cargo test --locked`, and `cargo clippy --locked` only after H and C converge. Stop for a required
unplanned path, API change, Cargo-lock collision, M2 plugin-root regression, Membrane requirement,
or claim that needs unavailable external qualification.
