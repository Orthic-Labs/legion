//! Integration-journal, previous-pointer, and receipt writers ported from
//! `qualify-windows-release.mjs`.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::windows_release_config::WindowsInstallContract;
use crate::windows_release_support::{has_forbidden_binding_segment, read_json};

#[allow(clippy::too_many_arguments)]
pub struct IntegrationJournalInput<'a> {
    pub state_root: &'a Path,
    pub current_path: &'a Path,
    pub previous_path: &'a Path,
    pub active_version_root: &'a Path,
    pub prior_version_root: Option<&'a Path>,
    pub target_version: &'a str,
    pub prior_version: Option<&'a str>,
    pub state_name: &'a str,
    pub prior_health: Option<&'a Value>,
    pub current_health: Option<&'a Value>,
}

/// Mirrors `integrationJournalRecord`.
pub fn integration_journal_record(input: IntegrationJournalInput) -> Value {
    let install_root = input.current_path.parent().unwrap_or(Path::new("."));
    let executable = input.current_path.join("bin").join("legion.exe");
    let next_path = install_root.join(WindowsInstallContract::NEXT_CURRENT_NAME);
    let active_health = input.current_health.or(input.prior_health);

    let integration = |health: Option<&Value>| {
        let complete = health.and_then(|h| h.get("complete")).and_then(|v| v.as_bool()).unwrap_or(false);
        json!({
            "state": if complete { "current" } else { "unproven" },
            "commandProofRef": health.and_then(|h| h.pointer("/qualificationProofs/commandPath")).cloned().unwrap_or(Value::Null),
            "qualificationEvidenceRef": health.and_then(|h| h.pointer("/qualificationProofs/qualificationPath")).cloned().unwrap_or(Value::Null),
            "healthSha256": health.and_then(|h| h.get("fingerprint")).cloned().unwrap_or(Value::Null),
        })
    };

    json!({
        "schemaVersion": 1,
        "kind": "legion-integration-journal",
        "state": input.state_name,
        "currentPath": input.current_path,
        "previousPath": input.previous_path,
        "activeVersionRoot": input.active_version_root,
        "priorVersionRoot": input.prior_version_root,
        "targetVersion": input.target_version,
        "priorVersion": input.prior_version,
        "priorHealthSha256": input.prior_health.and_then(|h| h.get("fingerprint")).cloned().unwrap_or(Value::Null),
        "origin": WindowsInstallContract::ORIGIN,
        "installRoot": install_root,
        "executable": executable,
        "generation": active_health.and_then(|h| h.get("generation")).cloned().unwrap_or(Value::Null),
        "nextPath": next_path,
        "switch": {
            "strategy": "journaled-atomic-replacement",
            "currentPath": input.current_path,
            "nextPath": next_path,
            "previousPath": input.previous_path,
        },
        "binding": {
            "origin": WindowsInstallContract::ORIGIN,
            "installRoot": install_root,
            "currentPath": input.current_path,
            "executable": executable,
            "generation": active_health.and_then(|h| h.get("generation")).cloned().unwrap_or(Value::Null),
            "resolvedVersionRoot": input.active_version_root,
        },
        "integrations": { "codex": integration(input.current_health.or(input.prior_health)) },
        "stateRoot": input.state_root,
    })
}

/// Mirrors `writeIntegrationJournal`.
pub fn write_integration_journal(path: &Path, record: Value) -> Result<Value, String> {
    if has_forbidden_binding_segment(&path.to_string_lossy()) {
        return Err(format!("integration journal path escapes installed state: {}", path.display()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = format!("{}\n", serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?);
    fs::write(path, text).map_err(|e| e.to_string())?;
    read_json(path, "integration journal")
}

/// Mirrors `writePointer`.
pub fn write_pointer(path: &Path, target: &Path) -> Result<bool, String> {
    let text = format!("{}\n", target.display());
    fs::write(path, &text).map_err(|e| e.to_string())?;
    let read_back = fs::read_to_string(path).map_err(|e| e.to_string())?;
    Ok(read_back.trim() == target.to_string_lossy())
}

/// Mirrors `writeReceipt` (write-to-temp then rename).
pub fn write_receipt(path: &Path, receipt: &Value) -> Result<PathBuf, String> {
    if path.exists() && path.is_dir() {
        return Err(format!("qualification receipt path is a directory: {}", path.display()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let temporary = PathBuf::from(format!("{}.{}.tmp", path.display(), std::process::id()));
    let text = format!("{}\n", serde_json::to_string_pretty(receipt).map_err(|e| e.to_string())?);
    let result = (|| -> Result<(), String> {
        fs::write(&temporary, &text).map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(path.to_path_buf())
}
