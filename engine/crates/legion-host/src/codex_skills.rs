//! Native Codex skill projection with ledger-gated ownership.
//!
//! Codex discovers plain Agent Skills at `$HOME/.agents/skills/<id>`.  Legion
//! copies each release package verbatim from `assets/skills`; it never prefixes
//! a skill id, transforms package contents, or claims a pre-existing tree.
//! A private ledger under Legion platform state is the sole authority to update
//! or remove a copied tree.

use crate::HostError;
use legion_contracts::canonical_digest;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const CODEX_SKILLS_OWNER: &str = "legion-host-codex-skills-v1";
pub const CODEX_SKILLS_LEDGER_RELATIVE_PATH: &str = "integrations/codex-skills.json";
const CODEX_SKILLS_LEDGER_SCHEMA_VERSION: u32 = 1;
const STAGE_ATTEMPTS: usize = 16;
static NEXT_NONCE: AtomicUsize = AtomicUsize::new(0);

/// Inputs come from an installed release plus host setup.  `assets_skills_root`
/// is the installed release's `assets/skills` directory, never a source tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexSkillsInput {
    pub home: PathBuf,
    pub assets_skills_root: PathBuf,
    pub platform_state_root: PathBuf,
    pub current_skill_ids: Vec<String>,
    #[serde(default)]
    pub retired_skill_ids: Vec<String>,
    pub generation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexSkillState {
    Healthy,
    Missing,
    Stale,
    Conflict,
    Foreign,
    RetiredOwned,
    RetiredMissing,
    RetiredConflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexSkillStatus {
    pub id: String,
    pub path: PathBuf,
    pub state: CodexSkillState,
    #[serde(default)]
    pub source_digest: Option<String>,
    #[serde(default)]
    pub ledger_digest: Option<String>,
    #[serde(default)]
    pub destination_digest: Option<String>,
    #[serde(default)]
    pub ledger_generation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexSkillOperationKind {
    Install,
    Update,
    Remove,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexSkillOperation {
    pub id: String,
    pub path: PathBuf,
    pub kind: CodexSkillOperationKind,
    #[serde(default)]
    pub source_digest: Option<String>,
    #[serde(default)]
    pub expected_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexSkillsInspection {
    pub destination_root: PathBuf,
    pub ledger_path: PathBuf,
    pub ledger_present: bool,
    #[serde(default)]
    pub ledger_error: Option<String>,
    pub statuses: Vec<CodexSkillStatus>,
    /// Entries Legion did not select or own.  They are informational only.
    pub unrelated_paths: Vec<PathBuf>,
    pub remediation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexSkillsPreview {
    pub inspection: CodexSkillsInspection,
    pub operations: Vec<CodexSkillOperation>,
    pub conflicts: Vec<CodexSkillStatus>,
    pub kept: Vec<CodexSkillStatus>,
    pub remediation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexSkillsApply {
    pub preview: CodexSkillsPreview,
    pub applied: Vec<CodexSkillOperation>,
    pub kept: Vec<CodexSkillStatus>,
    pub remediation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CodexSkillsLedger {
    schema_version: u32,
    owner: String,
    entries: BTreeMap<String, CodexSkillsLedgerEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CodexSkillsLedgerEntry {
    digest: String,
    generation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PackageTree {
    directories: Vec<String>,
    files: Vec<PackageFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PackageFile {
    path: String,
    bytes: Vec<u8>,
}

impl PackageTree {
    fn digest(&self) -> Result<String, HostError> {
        canonical_digest(self).map_err(|error| HostError::SemanticBlocker {
            reason: format!("cannot digest Codex skill package: {error}"),
        })
    }
}

enum LedgerRead {
    Absent,
    Valid(CodexSkillsLedger),
    Invalid(String),
}

enum DestinationTree {
    Absent,
    Digest(String),
    Invalid,
}

/// Read Codex plain-skill state without modifying user or platform files.
pub fn inspect_codex_skills(input: &CodexSkillsInput) -> Result<CodexSkillsInspection, HostError> {
    let normalized = normalized_input(input)?;
    let destination_root = codex_destination_root(&input.home);
    let ledger_path = ledger_path(&input.platform_state_root);
    let sources = current_sources(input, &normalized.current)?;
    let ledger_read = read_ledger(&ledger_path)?;
    let (ledger_present, ledger_error, ledger) = match ledger_read {
        LedgerRead::Absent => (false, None, None),
        LedgerRead::Valid(ledger) => (true, None, Some(ledger)),
        LedgerRead::Invalid(error) => (true, Some(error), None),
    };
    let destination_ok = destination_root_kind(&destination_root)?;
    let mut retirement_ids = normalized.retired;
    if let Some(ledger) = &ledger {
        retirement_ids.extend(
            ledger
                .entries
                .keys()
                .filter(|id| !normalized.current.contains(*id))
                .cloned(),
        );
    }
    retirement_ids.sort();
    retirement_ids.dedup();

    let mut statuses = Vec::new();
    let mut remediation = Vec::new();
    if !destination_ok {
        remediation.push(
            "Codex skills root is not a regular directory; Legion will not traverse or replace it."
                .into(),
        );
    }
    if let Some(error) = &ledger_error {
        remediation.push(format!(
            "Codex skill ownership ledger is invalid ({error}); repair will not claim, update, or remove any projection."
        ));
    }

    for id in &normalized.current {
        let source_digest = sources.get(id).map(|tree| tree.digest()).transpose()?;
        let path = destination_root.join(id);
        let destination = if destination_ok {
            destination_tree(&path)?
        } else {
            DestinationTree::Invalid
        };
        let entry = ledger.as_ref().and_then(|ledger| ledger.entries.get(id));
        let state = current_state(
            &destination,
            entry,
            source_digest.as_deref(),
            ledger_error.is_some(),
        );
        if matches!(state, CodexSkillState::Missing) {
            remediation.push(format!(
                "Codex plain skill {id} is missing; apply current installed release projection."
            ));
        }
        if matches!(state, CodexSkillState::Stale) {
            remediation.push(format!(
                "Codex plain skill {id} is an unchanged Legion projection from an older generation; repair can refresh it."
            ));
        }
        statuses.push(CodexSkillStatus {
            id: id.clone(),
            path,
            state,
            source_digest,
            ledger_digest: entry.map(|entry| entry.digest.clone()),
            destination_digest: destination_digest(&destination),
            ledger_generation: entry.map(|entry| entry.generation.clone()),
        });
    }

    for id in &retirement_ids {
        let path = destination_root.join(id);
        let destination = if destination_ok {
            destination_tree(&path)?
        } else {
            DestinationTree::Invalid
        };
        let entry = ledger.as_ref().and_then(|ledger| ledger.entries.get(id));
        let state = retired_state(&destination, entry, ledger_error.is_some());
        if matches!(state, CodexSkillState::RetiredOwned) {
            remediation.push(format!(
                "Retired Legion Codex skill {id} is intact and can be removed safely."
            ));
        }
        if matches!(
            state,
            CodexSkillState::RetiredConflict | CodexSkillState::Foreign
        ) {
            remediation.push(format!(
                "Retired Codex skill {id} is preserved because Legion ownership is unproven."
            ));
        }
        statuses.push(CodexSkillStatus {
            id: id.clone(),
            path,
            state,
            source_digest: None,
            ledger_digest: entry.map(|entry| entry.digest.clone()),
            destination_digest: destination_digest(&destination),
            ledger_generation: entry.map(|entry| entry.generation.clone()),
        });
    }

    let selected = statuses
        .iter()
        .map(|status| status.id.as_str())
        .collect::<BTreeSet<_>>();
    let unrelated_paths = unrelated_destination_paths(&destination_root, &selected)?;
    statuses.sort_by(|left, right| left.id.cmp(&right.id));
    remediation.sort();
    remediation.dedup();
    Ok(CodexSkillsInspection {
        destination_root,
        ledger_path,
        ledger_present,
        ledger_error,
        statuses,
        unrelated_paths,
        remediation,
    })
}

/// Produce a non-mutating desired-state plan.  It includes safe retirement
/// cleanup, but no operation is emitted for a conflict or unowned directory.
pub fn preview_codex_skills(input: &CodexSkillsInput) -> Result<CodexSkillsPreview, HostError> {
    let inspection = inspect_codex_skills(input)?;
    let mut operations = Vec::new();
    let mut conflicts = Vec::new();
    let mut kept = Vec::new();
    if inspection.ledger_error.is_none() {
        for status in &inspection.statuses {
            let kind = match status.state {
                CodexSkillState::Missing => Some(CodexSkillOperationKind::Install),
                CodexSkillState::Stale => Some(CodexSkillOperationKind::Update),
                CodexSkillState::RetiredOwned => Some(CodexSkillOperationKind::Remove),
                CodexSkillState::Conflict | CodexSkillState::RetiredConflict => {
                    conflicts.push(status.clone());
                    None
                }
                CodexSkillState::Foreign => {
                    kept.push(status.clone());
                    None
                }
                CodexSkillState::Healthy | CodexSkillState::RetiredMissing => None,
            };
            if let Some(kind) = kind {
                operations.push(CodexSkillOperation {
                    id: status.id.clone(),
                    path: status.path.clone(),
                    kind,
                    source_digest: status.source_digest.clone(),
                    expected_digest: status.ledger_digest.clone(),
                });
            }
        }
    } else {
        conflicts.extend(
            inspection
                .statuses
                .iter()
                .filter(|status| {
                    !matches!(
                        status.state,
                        CodexSkillState::Healthy | CodexSkillState::RetiredMissing
                    )
                })
                .cloned(),
        );
    }
    let mut remediation = inspection.remediation.clone();
    for status in &conflicts {
        remediation.push(format!(
            "Codex skill {} conflicts with Legion ownership ledger; preserve it until user resolution.",
            status.id
        ));
    }
    operations.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| kind_order(left.kind).cmp(&kind_order(right.kind)))
    });
    conflicts.sort_by(|left, right| left.id.cmp(&right.id));
    kept.sort_by(|left, right| left.id.cmp(&right.id));
    remediation.sort();
    remediation.dedup();
    Ok(CodexSkillsPreview {
        inspection,
        operations,
        conflicts,
        kept,
        remediation,
    })
}

/// Apply safe current projections plus safe retirement cleanup.  Every mutation
/// rechecks ledger ownership immediately before it changes a destination.
pub fn apply_codex_skills(input: &CodexSkillsInput) -> Result<CodexSkillsApply, HostError> {
    reconcile_codex_skills(input)
}

/// Repair is an idempotent alias for current-release reconciliation.
pub fn repair_codex_skills(input: &CodexSkillsInput) -> Result<CodexSkillsApply, HostError> {
    reconcile_codex_skills(input)
}

/// Preview removal of every intact ledger-owned Codex projection. Modified,
/// foreign, or otherwise unproven trees remain conflicts/kept entries.
pub fn preview_remove_codex_skills(
    input: &CodexSkillsInput,
) -> Result<CodexSkillsPreview, HostError> {
    let inspection = inspect_codex_skills(input)?;
    let mut operations = Vec::new();
    let mut conflicts = Vec::new();
    let mut kept = Vec::new();
    if inspection.ledger_error.is_none() {
        for status in &inspection.statuses {
            if matches!(
                status.state,
                CodexSkillState::Healthy | CodexSkillState::Stale | CodexSkillState::RetiredOwned
            ) || (matches!(status.state, CodexSkillState::Missing)
                && status.ledger_digest.is_some())
            {
                operations.push(CodexSkillOperation {
                    id: status.id.clone(),
                    path: status.path.clone(),
                    kind: CodexSkillOperationKind::Remove,
                    source_digest: None,
                    expected_digest: status.ledger_digest.clone(),
                });
            } else if matches!(
                status.state,
                CodexSkillState::Conflict | CodexSkillState::RetiredConflict
            ) {
                conflicts.push(status.clone());
            } else if matches!(status.state, CodexSkillState::Foreign) {
                kept.push(status.clone());
            }
        }
    } else {
        conflicts.extend(
            inspection
                .statuses
                .iter()
                .filter(|status| {
                    !matches!(
                        status.state,
                        CodexSkillState::RetiredMissing | CodexSkillState::Missing
                    )
                })
                .cloned(),
        );
    }
    operations.sort_by(|left, right| left.id.cmp(&right.id));
    conflicts.sort_by(|left, right| left.id.cmp(&right.id));
    kept.sort_by(|left, right| left.id.cmp(&right.id));
    let mut remediation = inspection.remediation.clone();
    for status in &conflicts {
        remediation.push(format!(
            "Codex skill {} is not safely removable; preserve it until user resolution.",
            status.id
        ));
    }
    remediation.sort();
    remediation.dedup();
    Ok(CodexSkillsPreview {
        inspection,
        operations,
        conflicts,
        kept,
        remediation,
    })
}

/// Remove only intact ledger-owned Codex projections.  Unrelated or modified
/// trees remain present and are returned as kept/conflict state.
pub fn remove_codex_skills(input: &CodexSkillsInput) -> Result<CodexSkillsApply, HostError> {
    let initial = preview_remove_codex_skills(input)?;
    let mut applied = Vec::new();
    let mut remediation = initial.remediation.clone();
    for operation in initial.operations {
        if execute_remove(input, &operation)? {
            applied.push(operation);
        } else {
            remediation.push(format!(
                "Kept Codex skill {} because ownership changed before removal.",
                operation.id
            ));
        }
    }
    finish_apply(input, applied, remediation)
}

fn reconcile_codex_skills(input: &CodexSkillsInput) -> Result<CodexSkillsApply, HostError> {
    let initial = preview_codex_skills(input)?;
    let mut applied = Vec::new();
    let mut remediation = initial.remediation.clone();
    for operation in initial.operations {
        let changed = match operation.kind {
            CodexSkillOperationKind::Install | CodexSkillOperationKind::Update => {
                execute_write(input, &operation)?
            }
            CodexSkillOperationKind::Remove => execute_remove(input, &operation)?,
        };
        if changed {
            applied.push(operation);
        } else {
            remediation.push(
                "Codex skill projection changed while repair was pending; it was preserved.".into(),
            );
        }
    }
    finish_apply(input, applied, remediation)
}

fn finish_apply(
    input: &CodexSkillsInput,
    mut applied: Vec<CodexSkillOperation>,
    mut remediation: Vec<String>,
) -> Result<CodexSkillsApply, HostError> {
    let preview = preview_codex_skills(input)?;
    applied.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| kind_order(left.kind).cmp(&kind_order(right.kind)))
    });
    remediation.extend(preview.remediation.iter().cloned());
    remediation.sort();
    remediation.dedup();
    Ok(CodexSkillsApply {
        kept: preview.kept.clone(),
        preview,
        applied,
        remediation,
    })
}

fn execute_write(
    input: &CodexSkillsInput,
    operation: &CodexSkillOperation,
) -> Result<bool, HostError> {
    let fresh = preview_codex_skills(input)?;
    let Some(current) = fresh
        .operations
        .iter()
        .find(|candidate| candidate.id == operation.id && candidate.kind == operation.kind)
    else {
        return Ok(false);
    };
    let expected_state = match current.kind {
        CodexSkillOperationKind::Install => CodexSkillState::Missing,
        CodexSkillOperationKind::Update => CodexSkillState::Stale,
        CodexSkillOperationKind::Remove => return Ok(false),
    };
    let status = fresh
        .inspection
        .statuses
        .iter()
        .find(|status| status.id == current.id)
        .ok_or_else(|| HostError::HarnessConflict {
            path: current.path.display().to_string(),
            reason: "Codex skill status disappeared during apply".into(),
        })?;
    if status.state != expected_state {
        return Ok(false);
    }
    let tree = source_tree(&input.assets_skills_root.join(&current.id))?;
    let source_digest = tree.digest()?;
    if current.source_digest.as_deref() != Some(source_digest.as_str()) {
        return Ok(false);
    }
    let root = ensure_destination_root(&input.home)?;
    let destination = root.join(&current.id);
    if destination != current.path {
        return Ok(false);
    }
    let ledger_path = ledger_path(&input.platform_state_root);
    let mut ledger = load_mutable_ledger(&ledger_path)?;
    let existing = ledger.entries.get(&current.id).cloned();
    if current.kind == CodexSkillOperationKind::Install {
        if !matches!(destination_tree(&destination)?, DestinationTree::Absent) {
            return Ok(false);
        }
        if existing.is_some()
            && existing.as_ref().map(|entry| entry.digest.as_str())
                != current.expected_digest.as_deref()
        {
            return Ok(false);
        }
    } else {
        let Some(existing) = existing.as_ref() else {
            return Ok(false);
        };
        if current.expected_digest.as_deref() != Some(existing.digest.as_str())
            || !matches!(destination_tree(&destination)?, DestinationTree::Digest(ref digest) if digest == &existing.digest)
        {
            return Ok(false);
        }
    }

    let stage = create_stage_directory(&root, &current.id, "stage")?;
    if let Err(error) = materialize_tree(&stage, &tree) {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }
    if package_digest_at(&stage)? != source_digest {
        let _ = fs::remove_dir_all(&stage);
        return Err(HostError::Verification {
            reason: format!(
                "staged Codex skill {} does not match canonical package",
                current.id
            ),
        });
    }

    ledger.entries.insert(
        current.id.clone(),
        CodexSkillsLedgerEntry {
            digest: source_digest,
            generation: input.generation.clone(),
        },
    );
    replace_with_stage(
        &destination,
        &stage,
        matches!(current.kind, CodexSkillOperationKind::Update),
        &ledger_path,
        &ledger,
    )
}

fn execute_remove(
    input: &CodexSkillsInput,
    operation: &CodexSkillOperation,
) -> Result<bool, HostError> {
    if operation.kind != CodexSkillOperationKind::Remove {
        return Ok(false);
    }
    let inspection = inspect_codex_skills(input)?;
    if inspection.ledger_error.is_some() {
        return Ok(false);
    }
    let Some(status) = inspection
        .statuses
        .iter()
        .find(|status| status.id == operation.id)
    else {
        return Ok(false);
    };
    let removes_missing_ledger =
        matches!(status.state, CodexSkillState::Missing) && status.ledger_digest.is_some();
    if !matches!(
        status.state,
        CodexSkillState::Healthy | CodexSkillState::Stale | CodexSkillState::RetiredOwned
    ) && !removes_missing_ledger
    {
        return Ok(false);
    }
    if status.ledger_digest.as_deref() != operation.expected_digest.as_deref() {
        return Ok(false);
    }
    let root = ensure_destination_root(&input.home)?;
    let destination = root.join(&operation.id);
    if destination != status.path {
        return Ok(false);
    }
    let ledger_path = ledger_path(&input.platform_state_root);
    let mut ledger = load_mutable_ledger(&ledger_path)?;
    let Some(entry) = ledger.entries.get(&operation.id).cloned() else {
        return Ok(false);
    };
    if operation.expected_digest.as_deref() != Some(entry.digest.as_str()) {
        return Ok(false);
    }
    match destination_tree(&destination)? {
        DestinationTree::Absent if removes_missing_ledger => {
            ledger.entries.remove(&operation.id);
            write_ledger(&ledger_path, &ledger)?;
            Ok(true)
        }
        DestinationTree::Digest(digest) if digest == entry.digest => {
            let backup = create_stage_directory(&root, &operation.id, "remove")?;
            fs::remove_dir(&backup).map_err(|error| io_error(&backup, error))?;
            fs::rename(&destination, &backup).map_err(|error| io_error(&destination, error))?;
            ledger.entries.remove(&operation.id);
            if let Err(error) = write_ledger(&ledger_path, &ledger) {
                rollback_rename(&backup, &destination)?;
                return Err(error);
            }
            fs::remove_dir_all(&backup).map_err(|error| io_error(&backup, error))?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn replace_with_stage(
    destination: &Path,
    stage: &Path,
    replacing: bool,
    ledger_path: &Path,
    ledger: &CodexSkillsLedger,
) -> Result<bool, HostError> {
    if !replacing {
        fs::rename(stage, destination).map_err(|error| io_error(destination, error))?;
        if let Err(error) = write_ledger(ledger_path, ledger) {
            let _ = fs::remove_dir_all(destination);
            return Err(error);
        }
        return Ok(true);
    }
    let root = destination.parent().ok_or_else(|| HostError::PathEscape {
        path: destination.display().to_string(),
        reason: "Codex skill destination has no parent".into(),
    })?;
    let id = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| HostError::PathEscape {
            path: destination.display().to_string(),
            reason: "Codex skill destination has no safe id".into(),
        })?;
    let backup = create_stage_directory(root, id, "backup")?;
    fs::remove_dir(&backup).map_err(|error| io_error(&backup, error))?;
    fs::rename(destination, &backup).map_err(|error| io_error(destination, error))?;
    if let Err(error) = fs::rename(stage, destination).map_err(|error| io_error(destination, error))
    {
        rollback_rename(&backup, destination)?;
        return Err(error);
    }
    if let Err(error) = write_ledger(ledger_path, ledger) {
        let rollback_stage = create_stage_directory(root, id, "rollback")?;
        fs::remove_dir(&rollback_stage).map_err(|io| io_error(&rollback_stage, io))?;
        fs::rename(destination, &rollback_stage).map_err(|io| io_error(destination, io))?;
        rollback_rename(&backup, destination)?;
        let _ = fs::remove_dir_all(&rollback_stage);
        return Err(error);
    }
    fs::remove_dir_all(&backup).map_err(|error| io_error(&backup, error))?;
    Ok(true)
}

fn rollback_rename(from: &Path, to: &Path) -> Result<(), HostError> {
    fs::rename(from, to).map_err(|error| HostError::Rollback {
        reason: format!(
            "cannot restore Codex skill {} from {}: {error}",
            to.display(),
            from.display()
        ),
    })
}

fn normalized_input(input: &CodexSkillsInput) -> Result<NormalizedInput, HostError> {
    if input.generation.trim().is_empty() {
        return Err(HostError::InvalidDescriptor {
            path: "codexSkills.generation".into(),
            reason: "generation must be non-empty".into(),
        });
    }
    let current = normalize_ids(&input.current_skill_ids, "currentSkillIds")?;
    let retired = normalize_ids(&input.retired_skill_ids, "retiredSkillIds")?;
    if current.iter().any(|id| retired.binary_search(id).is_ok()) {
        return Err(HostError::InvalidDescriptor {
            path: "codexSkills.retiredSkillIds".into(),
            reason: "a skill id cannot be both current and retired".into(),
        });
    }
    Ok(NormalizedInput { current, retired })
}

struct NormalizedInput {
    current: Vec<String>,
    retired: Vec<String>,
}

fn normalize_ids(ids: &[String], field: &str) -> Result<Vec<String>, HostError> {
    let mut result = BTreeSet::new();
    for id in ids {
        if !safe_plain_id(id) {
            return Err(HostError::InvalidDescriptor {
                path: format!("codexSkills.{field}"),
                reason: format!("skill id {id:?} must be a lowercase plain skill id"),
            });
        }
        result.insert(id.clone());
    }
    Ok(result.into_iter().collect())
}

fn safe_plain_id(id: &str) -> bool {
    !id.is_empty()
        && id.as_bytes().iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (*byte == b'-' && index > 0 && index + 1 < id.len())
        })
        && !id.contains("--")
}

fn codex_destination_root(home: &Path) -> PathBuf {
    home.join(".agents").join("skills")
}

fn ledger_path(platform_state_root: &Path) -> PathBuf {
    platform_state_root.join(CODEX_SKILLS_LEDGER_RELATIVE_PATH)
}

fn current_sources(
    input: &CodexSkillsInput,
    ids: &[String],
) -> Result<BTreeMap<String, PackageTree>, HostError> {
    let mut sources = BTreeMap::new();
    for id in ids {
        sources.insert(id.clone(), source_tree(&input.assets_skills_root.join(id))?);
    }
    Ok(sources)
}

fn source_tree(path: &Path) -> Result<PackageTree, HostError> {
    let tree = package_tree(path, true).map_err(|reason| HostError::SourceDrift {
        path: path.display().to_string(),
        reason,
    })?;
    if !tree.files.iter().any(|file| file.path == "SKILL.md")
        || !tree
            .files
            .iter()
            .any(|file| file.path == "agents/openai.yaml")
    {
        return Err(HostError::SourceDrift {
            path: path.display().to_string(),
            reason: "native Codex package must include SKILL.md and agents/openai.yaml".into(),
        });
    }
    Ok(tree)
}

fn package_digest_at(path: &Path) -> Result<String, HostError> {
    let tree = package_tree(path, true).map_err(|reason| HostError::Verification {
        reason: format!(
            "cannot read projected Codex skill {}: {reason}",
            path.display()
        ),
    })?;
    tree.digest()
}

fn destination_tree(path: &Path) -> Result<DestinationTree, HostError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(DestinationTree::Absent),
        Err(error) => Err(io_error(path, error)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Ok(DestinationTree::Invalid)
        }
        Ok(_) => match package_tree(path, true) {
            Ok(tree) => Ok(DestinationTree::Digest(tree.digest()?)),
            Err(_) => Ok(DestinationTree::Invalid),
        },
    }
}

fn destination_digest(destination: &DestinationTree) -> Option<String> {
    match destination {
        DestinationTree::Digest(digest) => Some(digest.clone()),
        DestinationTree::Absent | DestinationTree::Invalid => None,
    }
}

fn current_state(
    destination: &DestinationTree,
    entry: Option<&CodexSkillsLedgerEntry>,
    source_digest: Option<&str>,
    ledger_invalid: bool,
) -> CodexSkillState {
    if ledger_invalid || matches!(destination, DestinationTree::Invalid) {
        return CodexSkillState::Conflict;
    }
    match destination {
        DestinationTree::Absent => CodexSkillState::Missing,
        DestinationTree::Digest(destination_digest) => match entry {
            Some(entry)
                if destination_digest == &entry.digest
                    && source_digest == Some(entry.digest.as_str()) =>
            {
                CodexSkillState::Healthy
            }
            Some(entry) if destination_digest == &entry.digest => CodexSkillState::Stale,
            Some(_) | None => CodexSkillState::Conflict,
        },
        DestinationTree::Invalid => CodexSkillState::Conflict,
    }
}

fn retired_state(
    destination: &DestinationTree,
    entry: Option<&CodexSkillsLedgerEntry>,
    ledger_invalid: bool,
) -> CodexSkillState {
    if ledger_invalid || matches!(destination, DestinationTree::Invalid) {
        return CodexSkillState::RetiredConflict;
    }
    match destination {
        DestinationTree::Absent => CodexSkillState::RetiredMissing,
        DestinationTree::Digest(destination_digest) => match entry {
            Some(entry) if destination_digest == &entry.digest => CodexSkillState::RetiredOwned,
            Some(_) => CodexSkillState::RetiredConflict,
            None => CodexSkillState::Foreign,
        },
        DestinationTree::Invalid => CodexSkillState::RetiredConflict,
    }
}

fn destination_root_kind(path: &Path) -> Result<bool, HostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Err(error) => Err(io_error(path, error)),
    }
}

fn unrelated_destination_paths(
    root: &Path,
    selected: &BTreeSet<&str>,
) -> Result<Vec<PathBuf>, HostError> {
    if !destination_root_kind(root)? {
        return Ok(Vec::new());
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(root, error)),
    };
    let mut unrelated = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(root, error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            unrelated.push(entry.path());
            continue;
        };
        if !selected.iter().any(|id| *id == name) {
            unrelated.push(entry.path());
        }
    }
    unrelated.sort();
    Ok(unrelated)
}

fn read_ledger(path: &Path) -> Result<LedgerRead, HostError> {
    ensure_ledger_parent_safe(path, false)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(LedgerRead::Absent),
        Err(error) => Err(io_error(path, error)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Ok(LedgerRead::Invalid("ledger is not a regular file".into()))
        }
        Ok(_) => {
            let bytes = fs::read(path).map_err(|error| io_error(path, error))?;
            let ledger: CodexSkillsLedger = match serde_json::from_slice(&bytes) {
                Ok(ledger) => ledger,
                Err(error) => return Ok(LedgerRead::Invalid(error.to_string())),
            };
            if ledger.schema_version != CODEX_SKILLS_LEDGER_SCHEMA_VERSION
                || ledger.owner != CODEX_SKILLS_OWNER
                || ledger.entries.iter().any(|(id, entry)| {
                    !safe_plain_id(id)
                        || entry.digest.trim().is_empty()
                        || entry.generation.trim().is_empty()
                })
            {
                return Ok(LedgerRead::Invalid(
                    "ledger schema, owner, or entry shape is invalid".into(),
                ));
            }
            Ok(LedgerRead::Valid(ledger))
        }
    }
}

fn load_mutable_ledger(path: &Path) -> Result<CodexSkillsLedger, HostError> {
    match read_ledger(path)? {
        LedgerRead::Absent => Ok(CodexSkillsLedger {
            schema_version: CODEX_SKILLS_LEDGER_SCHEMA_VERSION,
            owner: CODEX_SKILLS_OWNER.into(),
            entries: BTreeMap::new(),
        }),
        LedgerRead::Valid(ledger) => Ok(ledger),
        LedgerRead::Invalid(reason) => Err(HostError::HarnessConflict {
            path: path.display().to_string(),
            reason: format!("Codex skill ownership ledger is invalid: {reason}"),
        }),
    }
}

fn write_ledger(path: &Path, ledger: &CodexSkillsLedger) -> Result<(), HostError> {
    ensure_ledger_parent_safe(path, true)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(HostError::HarnessConflict {
                path: path.display().to_string(),
                reason: "Codex skill ownership ledger is not a replaceable regular file".into(),
            });
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(path, error)),
        Ok(_) => {}
    }
    let bytes = serde_json::to_vec_pretty(ledger).map_err(HostError::from)?;
    atomic_write(path, &bytes)
}

fn ensure_ledger_parent_safe(path: &Path, create: bool) -> Result<(), HostError> {
    let parent = path.parent().ok_or_else(|| HostError::PathEscape {
        path: path.display().to_string(),
        reason: "Codex ledger has no parent".into(),
    })?;
    let state_root = parent.parent().ok_or_else(|| HostError::PathEscape {
        path: path.display().to_string(),
        reason: "Codex ledger lacks platform-state parent".into(),
    })?;
    match fs::symlink_metadata(state_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(HostError::PathEscape {
                path: state_root.display().to_string(),
                reason: "platform-state root is not a regular directory".into(),
            });
        }
        Err(error) if error.kind() == ErrorKind::NotFound && create => {
            fs::create_dir_all(state_root).map_err(|error| io_error(state_root, error))?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(state_root, error)),
        Ok(_) => {}
    }
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(HostError::PathEscape {
                path: parent.display().to_string(),
                reason: "platform-state integrations path is not a regular directory".into(),
            });
        }
        Err(error) if error.kind() == ErrorKind::NotFound && create => {
            fs::create_dir(parent).map_err(|error| io_error(parent, error))?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(parent, error)),
        Ok(_) => {}
    }
    Ok(())
}

fn ensure_destination_root(home: &Path) -> Result<PathBuf, HostError> {
    let agents = home.join(".agents");
    ensure_regular_directory(&agents)?;
    let skills = agents.join("skills");
    ensure_regular_directory(&skills)?;
    Ok(skills)
}

fn ensure_regular_directory(path: &Path) -> Result<(), HostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(HostError::PathEscape {
                path: path.display().to_string(),
                reason: "Codex skill path is not a regular directory".into(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
                Ok(_) => Err(HostError::PathEscape {
                    path: path.display().to_string(),
                    reason: "Codex skill path changed while it was created".into(),
                }),
                Err(error) => Err(io_error(path, error)),
            }
        }
        Err(error) => Err(io_error(path, error)),
    }
}

fn package_tree(root: &Path, require_directory: bool) -> Result<PackageTree, String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || (require_directory && !metadata.is_dir()) {
        return Err("package root is not a regular directory".into());
    }
    let mut directories = Vec::new();
    let mut files = Vec::new();
    read_package_tree(root, root, &mut directories, &mut files)?;
    directories.sort();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(PackageTree { directories, files })
}

fn read_package_tree(
    root: &Path,
    current: &Path,
    directories: &mut Vec<String>,
    files: &mut Vec<PackageFile>,
) -> Result<(), String> {
    let entries = fs::read_dir(current).map_err(|error| error.to_string())?;
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(|left| left.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "package path escapes root".to_owned())?;
        let relative = normalized_relative(relative)?;
        if metadata.file_type().is_symlink() {
            return Err(format!("package contains symlink {relative}"));
        }
        if metadata.is_dir() {
            directories.push(relative);
            read_package_tree(root, &path, directories, files)?;
        } else if metadata.is_file() {
            files.push(PackageFile {
                path: relative,
                bytes: fs::read(&path).map_err(|error| error.to_string())?,
            });
        } else {
            return Err(format!("package contains unsupported entry {relative}"));
        }
    }
    Ok(())
}

fn normalized_relative(path: &Path) -> Result<String, String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => components.push(
                part.to_str()
                    .ok_or_else(|| "package path is not valid UTF-8".to_owned())?
                    .to_owned(),
            ),
            _ => return Err("package path has unsafe component".into()),
        }
    }
    if components.is_empty() {
        return Err("package path is empty".into());
    }
    Ok(components.join("/"))
}

fn materialize_tree(root: &Path, tree: &PackageTree) -> Result<(), HostError> {
    for directory in &tree.directories {
        let path = contained_child(root, directory)?;
        fs::create_dir_all(&path).map_err(|error| io_error(&path, error))?;
    }
    for file in &tree.files {
        let path = contained_child(root, &file.path)?;
        let parent = path.parent().ok_or_else(|| HostError::PathEscape {
            path: path.display().to_string(),
            reason: "Codex skill file has no parent".into(),
        })?;
        fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| io_error(&path, error))?;
        output
            .write_all(&file.bytes)
            .map_err(|error| io_error(&path, error))?;
        output.sync_all().map_err(|error| io_error(&path, error))?;
    }
    Ok(())
}

fn contained_child(root: &Path, relative: &str) -> Result<PathBuf, HostError> {
    let candidate = Path::new(relative);
    if relative.trim().is_empty()
        || candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(HostError::PathEscape {
            path: relative.into(),
            reason: "Codex package entry escapes destination".into(),
        });
    }
    Ok(root.join(candidate))
}

fn create_stage_directory(root: &Path, id: &str, label: &str) -> Result<PathBuf, HostError> {
    for _ in 0..STAGE_ATTEMPTS {
        let path = root.join(format!(".legion-{id}-{label}-{}", nonce()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(&path, error)),
        }
    }
    Err(HostError::BoundExceeded {
        reason: "could not allocate a unique Codex skill staging directory".into(),
    })
}

fn nonce() -> String {
    let sequence = NEXT_NONCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}-{sequence}", std::process::id())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    let parent = path.parent().ok_or_else(|| HostError::PathEscape {
        path: path.display().to_string(),
        reason: "Codex ledger has no parent".into(),
    })?;
    let temporary = parent.join(format!(".codex-skills-ledger-{}.tmp", nonce()));
    {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| io_error(&temporary, error))?;
        output
            .write_all(bytes)
            .map_err(|error| io_error(&temporary, error))?;
        output
            .sync_all()
            .map_err(|error| io_error(&temporary, error))?;
    }
    fs::rename(&temporary, path).map_err(|error| io_error(path, error))
}

fn kind_order(kind: CodexSkillOperationKind) -> u8 {
    match kind {
        CodexSkillOperationKind::Install => 0,
        CodexSkillOperationKind::Update => 1,
        CodexSkillOperationKind::Remove => 2,
    }
}

fn io_error(path: &Path, error: std::io::Error) -> HostError {
    HostError::Io {
        path: path.into(),
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "legion-host-codex-skills-{label}-{}-{nanos}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_skill(root: &Path, id: &str, body: &str) {
        let package = root.join(id);
        fs::create_dir_all(package.join("agents")).unwrap();
        fs::create_dir_all(package.join("references")).unwrap();
        fs::write(package.join("SKILL.md"), body).unwrap();
        fs::write(
            package.join("agents").join("openai.yaml"),
            "policy:\n  allow_implicit_invocation: false\n",
        )
        .unwrap();
        fs::write(
            package.join("references").join("guide.md"),
            format!("guide:{body}"),
        )
        .unwrap();
    }

    fn input(
        temp: &TempRoot,
        ids: &[&str],
        retired: &[&str],
        generation: &str,
    ) -> CodexSkillsInput {
        CodexSkillsInput {
            home: temp.0.join("home"),
            assets_skills_root: temp.0.join("assets").join("skills"),
            platform_state_root: temp.0.join("state"),
            current_skill_ids: ids.iter().map(|id| (*id).into()).collect(),
            retired_skill_ids: retired.iter().map(|id| (*id).into()).collect(),
            generation: generation.into(),
        }
    }

    #[test]
    fn apply_copies_full_plain_package_and_writes_ownership_ledger() {
        let temp = TempRoot::new("copy-full-package");
        let input = input(&temp, &["audit"], &[], "dev.1");
        write_skill(&input.assets_skills_root, "audit", "audit v1");

        let preview = preview_codex_skills(&input).unwrap();
        assert_eq!(preview.operations.len(), 1);
        assert_eq!(preview.operations[0].kind, CodexSkillOperationKind::Install);

        let applied = apply_codex_skills(&input).unwrap();
        assert_eq!(applied.applied.len(), 1);
        let destination = input.home.join(".agents").join("skills").join("audit");
        assert_eq!(fs::read(destination.join("SKILL.md")).unwrap(), b"audit v1");
        assert!(destination.join("agents").join("openai.yaml").exists());
        assert_eq!(
            fs::read(destination.join("references").join("guide.md")).unwrap(),
            b"guide:audit v1"
        );
        assert!(ledger_path(&input.platform_state_root).is_file());
        assert_eq!(
            inspect_codex_skills(&input).unwrap().statuses[0].state,
            CodexSkillState::Healthy
        );
    }

    #[test]
    fn update_requires_ledger_digest_and_preserves_user_modified_tree() {
        let temp = TempRoot::new("ledger-gated-update");
        let input_v1 = input(&temp, &["audit"], &[], "dev.1");
        write_skill(&input_v1.assets_skills_root, "audit", "audit v1");
        apply_codex_skills(&input_v1).unwrap();

        write_skill(&input_v1.assets_skills_root, "audit", "audit v2");
        let input_v2 = CodexSkillsInput {
            generation: "dev.2".into(),
            ..input_v1.clone()
        };
        assert_eq!(
            inspect_codex_skills(&input_v2).unwrap().statuses[0].state,
            CodexSkillState::Stale
        );
        repair_codex_skills(&input_v2).unwrap();
        let destination = input_v2.home.join(".agents").join("skills").join("audit");
        assert_eq!(fs::read(destination.join("SKILL.md")).unwrap(), b"audit v2");

        fs::write(destination.join("SKILL.md"), "user fork").unwrap();
        write_skill(&input_v2.assets_skills_root, "audit", "audit v3");
        let input_v3 = CodexSkillsInput {
            generation: "dev.3".into(),
            ..input_v2.clone()
        };
        let preview = preview_codex_skills(&input_v3).unwrap();
        assert_eq!(
            preview.inspection.statuses[0].state,
            CodexSkillState::Conflict
        );
        assert!(preview.operations.is_empty());
        assert_eq!(
            fs::read(destination.join("SKILL.md")).unwrap(),
            b"user fork"
        );
    }

    #[test]
    fn repair_removes_retired_owned_skill_and_preserves_unrelated_directory() {
        let temp = TempRoot::new("retired-owned");
        let current = input(&temp, &["audit"], &[], "dev.1");
        write_skill(&current.assets_skills_root, "audit", "audit v1");
        apply_codex_skills(&current).unwrap();
        let skills_root = current.home.join(".agents").join("skills");
        fs::create_dir_all(skills_root.join("content")).unwrap();
        fs::write(skills_root.join("content").join("SKILL.md"), "personal").unwrap();

        let retired = CodexSkillsInput {
            current_skill_ids: Vec::new(),
            retired_skill_ids: vec!["audit".into()],
            generation: "dev.2".into(),
            ..current.clone()
        };
        let repair = repair_codex_skills(&retired).unwrap();
        assert_eq!(repair.applied.len(), 1);
        assert_eq!(repair.applied[0].kind, CodexSkillOperationKind::Remove);
        assert!(!skills_root.join("audit").exists());
        assert!(skills_root.join("content").exists());
        assert!(repair
            .preview
            .inspection
            .unrelated_paths
            .contains(&skills_root.join("content")));
    }
}
