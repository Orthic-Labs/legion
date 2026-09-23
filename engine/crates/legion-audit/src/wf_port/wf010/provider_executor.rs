//! Port of `src/lib/providers/provider-executor.mjs`'s dispatcher and its
//! `resolveRepositoryModule` path-safety guard.
//!
//! `legacy-check` and `reasoning-contract` are ported as a generic dispatch
//! over host-supplied async hooks (there is no native `host.processRunner`
//! / `host.reviewer` equivalent in this crate to call directly).
//!
//! `runtime-script` / `security-pack` (`runRuntimeScript`) and
//! `external-process` (`runExternal`, ported in
//! [`super::external_process::run_external`]) dispatch the same way the JS
//! does; `imported-artifact` is a pure function ported directly.
//!
//! GAP: JS `runRuntimeScript` performs a dynamic `import()` of a
//! JS-language provider module at a sealed, digest-pinned path, then invokes
//! its exported `analyze` function. There is no Rust analogue of loading and
//! invoking an arbitrary JS module at runtime; a native `runtime-script`
//! provider is instead a compiled Rust function the plan's runner record
//! names by key. That lookup/dispatch is out of this chunk's scope (it
//! lives with whatever registers native providers), so this port only
//! carries over `resolveRepositoryModule`'s path-safety check, which is
//! reusable by such a lookup.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Faithful port of `resolveRepositoryModule(script)`.
///
/// Rejects a `script` that is a POSIX absolute path (`/...`) or a Windows
/// drive-absolute path (`C:\...`), matching the JS regex
/// `/^[a-zA-Z]:[\\/]/`. `repository_root` stands in for the three
/// `resolve(import.meta.dirname, '..', '..', '..', script)` hops in JS,
/// i.e. the Legion package/repository root.
pub fn resolve_repository_module(script: &str, repository_root: &Path) -> Result<PathBuf, RepositoryModuleError> {
    if script.is_empty() {
        return Err(RepositoryModuleError::MissingModule);
    }
    let is_windows_drive_absolute = script.len() >= 3
        && script.as_bytes()[0].is_ascii_alphabetic()
        && script.as_bytes()[1] == b':'
        && matches!(script.as_bytes()[2], b'\\' | b'/');
    if script.starts_with('/') || is_windows_drive_absolute {
        return Err(RepositoryModuleError::NotRepositoryRelative { script: script.to_string() });
    }
    Ok(repository_root.join(script))
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RepositoryModuleError {
    #[error("runtime-script requires sealed module path")]
    MissingModule,
    #[error("runtime-script path must be repository-relative: {script}")]
    NotRepositoryRelative { script: String },
}

/// Mirrors the minimal provider-result shape every branch of
/// `executePlannedProvider` returns on its unproven / missing / error paths.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProviderOutcome {
    pub provider: String,
    pub status: String,
    pub complete: bool,
    #[serde(default)]
    pub coverage_gaps: Vec<Value>,
    #[serde(default)]
    pub findings: Vec<Value>,
    #[serde(default)]
    pub candidates: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
}

fn gap(kind: &str) -> Value {
    serde_json::json!({ "kind": kind })
}

fn gap_with(kind: &str, key: &str, value: &str) -> Value {
    serde_json::json!({ "kind": kind, key: value })
}

/// Faithful port of `runImportedArtifact(provider, artifacts, host)`.
///
/// `artifacts` mirrors the JS `Map<string, unknown>` keyed by artifact name;
/// only presence is inspected, matching JS (`artifacts?.get(...)` truthy
/// check).
pub fn run_imported_artifact(provider_id: &str, artifact_name: &str, artifacts: &std::collections::BTreeMap<String, Value>) -> ProviderOutcome {
    if !artifacts.contains_key(artifact_name) {
        return ProviderOutcome {
            provider: provider_id.to_string(),
            status: "missing".to_string(),
            complete: false,
            coverage_gaps: vec![gap_with("imported-artifact-missing", "artifact", artifact_name)],
            findings: vec![],
            candidates: vec![],
            artifact: None,
        };
    }
    ProviderOutcome {
        provider: provider_id.to_string(),
        status: "pass".to_string(),
        complete: true,
        coverage_gaps: vec![],
        findings: vec![],
        candidates: vec![],
        artifact: Some(artifact_name.to_string()),
    }
}

/// Faithful port of the `default:` branch of `executePlannedProvider`'s
/// `switch (provider.runner?.kind)`.
pub fn unsupported_runner(provider_id: &str, runner_kind: Option<&str>) -> ProviderOutcome {
    ProviderOutcome {
        provider: provider_id.to_string(),
        status: "error".to_string(),
        complete: false,
        coverage_gaps: vec![serde_json::json!({
            "kind": "unsupported-runner",
            "runner": runner_kind,
        })],
        findings: vec![],
        candidates: vec![],
        artifact: None,
    }
}

/// Faithful port of `runReasoning`'s / `runLegacyCheck`'s shared
/// "host hook unavailable" short-circuit: both bail out to an `unproven`
/// result naming the missing capability when the host cannot service the
/// request, rather than erroring.
pub fn host_hook_unavailable(provider_id: &str, gap_kind: &str) -> ProviderOutcome {
    ProviderOutcome {
        provider: provider_id.to_string(),
        status: "unproven".to_string(),
        complete: false,
        coverage_gaps: vec![gap(gap_kind)],
        findings: vec![],
        candidates: vec![],
        artifact: None,
    }
}

/// Faithful port of `runLegacyCheck`'s / `runReasoning`'s receipt-invalid
/// short-circuit (`typeof result.complete !== 'boolean'`), and their
/// success path otherwise, given the receipt already fetched by the caller
/// from its host hook (`host.processRunner.run` / `host.reviewer.review`).
pub fn from_host_receipt(provider_id: &str, receipt: Option<&Value>, invalid_gap_kind: &str) -> ProviderOutcome {
    let complete = receipt.and_then(|r| r.get("complete")).and_then(Value::as_bool);
    let Some(complete) = complete else {
        return ProviderOutcome {
            provider: provider_id.to_string(),
            status: "unproven".to_string(),
            complete: false,
            coverage_gaps: vec![gap(invalid_gap_kind)],
            findings: vec![],
            candidates: vec![],
            artifact: None,
        };
    };
    let receipt = receipt.unwrap();
    let status = receipt.get("status").and_then(Value::as_str).unwrap_or("unproven").to_string();
    let findings = receipt.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
    let candidates = receipt.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default();
    let coverage_gaps = receipt.get("coverageGaps").and_then(Value::as_array).cloned().unwrap_or_default();
    ProviderOutcome {
        provider: provider_id.to_string(),
        status,
        complete,
        coverage_gaps,
        findings,
        candidates,
        artifact: None,
    }
}
