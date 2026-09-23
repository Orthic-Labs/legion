//! Integration tests porting JS coverage for
//! `src/lib/providers/{executor/runtime-module.mjs, executor/tool-identity.mjs,
//! external-process.mjs, provider-executor.mjs, registry.mjs}`
//! (see `../../../../tests/provider-executor.test.mjs` in the JS tree for
//! the `external-process.mjs`/`provider-executor.mjs` coverage this mirrors).
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod
//! wf010;` inside it) into `legion_audit`'s crate root.

use std::collections::BTreeMap;
use std::path::PathBuf;

use legion_audit::wf_port::wf010::external_process::{
    blocked, pick_environment, run_external, RunExternalHost, RunExternalSpec,
};
use legion_audit::wf_port::wf010::provider_executor::{
    host_hook_unavailable, resolve_repository_module, run_imported_artifact, unsupported_runner,
    RepositoryModuleError,
};
use legion_audit::wf_port::wf010::registry::{resolve, select, RegistryError};
use legion_audit::wf_port::wf010::runtime_module::{
    verify_module_provider_id, verify_sealed_runtime_module, RuntimeModuleError,
};
use legion_audit::wf_port::wf010::tool_identity::{qualify_tool, ToolStatus};

fn node_executable() -> String {
    std::env::var("NODE_EXECUTABLE").unwrap_or_else(|_| "node".to_string())
}

fn node_available() -> bool {
    std::process::Command::new(node_executable())
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------
// tool-identity.mjs (`qualifyTool`)
// ---------------------------------------------------------------------

#[tokio::test]
async fn qualify_tool_reports_missing_executable_for_unresolvable_command() {
    let result = qualify_tool(
        "definitely-not-a-real-executable-legion-wf010",
        &["--version".to_string()],
        None,
        &[],
        2000,
    )
    .await;
    assert_eq!(result.status, ToolStatus::MissingExecutable);
    assert_eq!(result.version, None);
    assert_eq!(result.executable_digest, None);
}

#[tokio::test]
async fn qualify_tool_reports_available_with_first_output_line_as_version() {
    if !node_available() {
        eprintln!("skipping: node not available");
        return;
    }
    let result = qualify_tool(
        &node_executable(),
        &["--version".to_string()],
        None,
        &[],
        5000,
    )
    .await;
    assert_eq!(result.status, ToolStatus::Available);
    assert!(result.version.is_some());
    assert!(!result.version.as_ref().unwrap().contains('\n'));
}

#[tokio::test]
async fn qualify_tool_digests_the_executable_only_when_absolute_and_present() {
    let result = qualify_tool("node", &["--version".to_string()], None, &[], 2000).await;
    // Relative/bare name ("node" resolved via PATH) never gets a digest,
    // matching JS `isAbsolute(executable) && existsSync(executable)`.
    assert_eq!(result.executable_digest, None);
}

// ---------------------------------------------------------------------
// external-process.mjs
// ---------------------------------------------------------------------

#[test]
fn pick_environment_only_carries_allowlisted_keys() {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/a".to_string());
    env.insert("HOME".to_string(), "/b".to_string());
    env.insert("SECRET".to_string(), "x".to_string());
    let picked = pick_environment(&env, &["PATH".to_string(), "HOME".to_string()]);
    assert_eq!(
        picked,
        vec![("PATH".to_string(), "/a".to_string()), ("HOME".to_string(), "/b".to_string())]
    );
}

#[test]
fn blocked_helper_produces_a_canonical_blocked_receipt() {
    let spec = RunExternalSpec {
        provider: Some("x".to_string()),
        executable: "tool".to_string(),
        cwd: Some("/tmp".to_string()),
        ..Default::default()
    };
    let receipt = blocked(&spec, "reason", "blocked");
    assert_eq!(receipt.spawn_status, "blocked");
    assert_eq!(receipt.kind, "legion-execution-result");
}

#[tokio::test]
async fn external_process_runner_blocks_non_allowlisted_executables() {
    let spec = RunExternalSpec {
        provider: Some("x".to_string()),
        executable: "rm".to_string(),
        args: vec!["-rf".to_string(), "/".to_string()],
        cwd: Some(".".to_string()),
        ..Default::default()
    };
    let host = RunExternalHost {
        allowed_executables: Some(vec!["node".to_string()]),
        ..Default::default()
    };
    let receipt = run_external(&spec, &host).await;
    assert_eq!(receipt.spawn_status, "blocked");
    assert_eq!(receipt.provider_result.status, "blocked");
    assert_eq!(receipt.provider_result.coverage_gaps[0].reason.as_deref(), Some("executable-not-allowlisted"));
}

#[tokio::test]
async fn shell_execution_is_forbidden() {
    let spec = RunExternalSpec {
        provider: Some("x".to_string()),
        executable: node_executable(),
        shell: true,
        ..Default::default()
    };
    let host = RunExternalHost::default();
    let joined = tokio::spawn(async move { run_external(&spec, &host).await }).await;
    assert!(joined.is_err() && joined.unwrap_err().is_panic());
}

#[tokio::test]
async fn external_process_runs_with_sanitized_environment() {
    if !node_available() {
        eprintln!("skipping: node not available");
        return;
    }
    let exe = which_absolute(&node_executable());
    let Some(exe) = exe else {
        eprintln!("skipping: could not resolve absolute node path");
        return;
    };
    let mut env = BTreeMap::new();
    env.insert("SECRET".to_string(), "leak".to_string());
    env.insert("PATH".to_string(), std::env::var("PATH").unwrap_or_default());
    let spec = RunExternalSpec {
        provider: Some("probe".to_string()),
        executable: exe.clone(),
        args: vec!["-e".to_string(), "process.exit(process.env.SECRET ? 1 : 0)".to_string()],
        cwd: Some(".".to_string()),
        environment_keys: vec!["PATH".to_string(), "HOME".to_string()],
        ..Default::default()
    };
    let host = RunExternalHost {
        allowed_executables: Some(vec![exe]),
        env,
        ..Default::default()
    };
    let receipt = run_external(&spec, &host).await;
    assert_eq!(receipt.spawn_status, "completed");
    assert_eq!(receipt.exit_code, Some(0));
}

#[tokio::test]
async fn timeout_aborts_the_child_and_reports_timeout() {
    if !node_available() {
        eprintln!("skipping: node not available");
        return;
    }
    let Some(exe) = which_absolute(&node_executable()) else {
        eprintln!("skipping: could not resolve absolute node path");
        return;
    };
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), std::env::var("PATH").unwrap_or_default());
    let spec = RunExternalSpec {
        provider: Some("slow".to_string()),
        executable: exe.clone(),
        args: vec!["-e".to_string(), "setTimeout(()=>{}, 60000)".to_string()],
        cwd: Some(".".to_string()),
        timeout_ms: Some(200),
        environment_keys: vec!["PATH".to_string(), "HOME".to_string()],
        ..Default::default()
    };
    let host = RunExternalHost { allowed_executables: Some(vec![exe]), env, ..Default::default() };
    let receipt = run_external(&spec, &host).await;
    assert_eq!(receipt.spawn_status, "timeout");
    assert!(receipt.timed_out);
}

fn which_absolute(name: &str) -> Option<String> {
    if PathBuf::from(name).is_absolute() {
        return Some(name.to_string());
    }
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return candidate.to_str().map(|s| s.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------
// provider-executor.mjs
// ---------------------------------------------------------------------

#[test]
fn resolve_repository_module_rejects_absolute_external_paths() {
    let root = PathBuf::from("/repo/root");
    assert_eq!(
        resolve_repository_module("/etc/evil.mjs", &root),
        Err(RepositoryModuleError::NotRepositoryRelative { script: "/etc/evil.mjs".to_string() })
    );
    assert_eq!(
        resolve_repository_module("C:\\evil.mjs", &root),
        Err(RepositoryModuleError::NotRepositoryRelative { script: "C:\\evil.mjs".to_string() })
    );
    let resolved = resolve_repository_module("src/providers/security-suite.mjs", &root).unwrap();
    assert!(resolved.ends_with("src/providers/security-suite.mjs"));
}

#[test]
fn reasoning_contract_providers_remain_unproven_when_reviewer_is_unavailable() {
    let outcome = host_hook_unavailable("security.adjudication", "reasoning-reviewer-unavailable");
    assert_eq!(outcome.status, "unproven");
    assert!(!outcome.complete);
    assert_eq!(outcome.coverage_gaps, vec![serde_json::json!({"kind": "reasoning-reviewer-unavailable"})]);
}

#[test]
fn imported_artifact_provider_requires_its_artifact() {
    let empty = BTreeMap::new();
    let missing = run_imported_artifact("codeql", "codeql.sarif", &empty);
    assert_eq!(missing.status, "missing");

    let mut present = BTreeMap::new();
    present.insert("codeql.sarif".to_string(), serde_json::json!({"path": "x"}));
    let outcome = run_imported_artifact("codeql", "codeql.sarif", &present);
    assert_eq!(outcome.status, "pass");
    assert!(outcome.complete);
    assert_eq!(outcome.artifact.as_deref(), Some("codeql.sarif"));
}

#[test]
fn unsupported_runner_kind_reports_error() {
    let outcome = unsupported_runner("weird.provider", Some("made-up-kind"));
    assert_eq!(outcome.status, "error");
    assert!(!outcome.complete);
    assert_eq!(
        outcome.coverage_gaps,
        vec![serde_json::json!({"kind": "unsupported-runner", "runner": "made-up-kind"})]
    );
}

// ---------------------------------------------------------------------
// runtime-module.mjs
// ---------------------------------------------------------------------

#[test]
fn verify_sealed_runtime_module_requires_script_and_digest() {
    let err = verify_sealed_runtime_module(None, None, &PathBuf::from("/pkg"), b"");
    assert_eq!(err, Err(RuntimeModuleError::MissingSealedRunner));
}

#[test]
fn verify_sealed_runtime_module_rejects_escaping_paths() {
    let err = verify_sealed_runtime_module(
        Some("../../etc/evil.mjs"),
        Some("sha256:deadbeef"),
        &PathBuf::from("/pkg/root"),
        b"anything",
    );
    assert_eq!(err, Err(RuntimeModuleError::EscapesPackageRoot));
}

#[test]
fn verify_sealed_runtime_module_rejects_digest_mismatch() {
    let err = verify_sealed_runtime_module(
        Some("renderer.mjs"),
        Some("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        &PathBuf::from("/pkg/root"),
        b"module body",
    );
    assert!(matches!(err, Err(RuntimeModuleError::DigestMismatch { .. })));
}

#[test]
fn verify_sealed_runtime_module_accepts_matching_digest_within_root() {
    let bytes = b"export const id = 'x'; export function render() {}";
    let digest = format!("sha256:{}", {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    });
    let resolved = verify_sealed_runtime_module(
        Some("renderer.mjs"),
        Some(&digest),
        &PathBuf::from("/pkg/root"),
        bytes,
    )
    .unwrap();
    assert!(resolved.ends_with("renderer.mjs"));
}

#[test]
fn verify_module_provider_id_rejects_mismatch_only_when_declared() {
    assert_eq!(verify_module_provider_id(None, "provider.x"), Ok(()));
    assert_eq!(verify_module_provider_id(Some("provider.x"), "provider.x"), Ok(()));
    assert_eq!(
        verify_module_provider_id(Some("provider.y"), "provider.x"),
        Err(RuntimeModuleError::ProviderMismatch { provider_id: "provider.x".to_string() })
    );
}

// ---------------------------------------------------------------------
// registry.mjs
// ---------------------------------------------------------------------

#[test]
fn registry_resolve_follows_aliases_then_requires_a_known_provider() {
    let mut by_id = BTreeMap::new();
    by_id.insert("security.credentials".to_string(), "provider-a");
    let mut aliases = BTreeMap::new();
    aliases.insert("creds".to_string(), "security.credentials".to_string());

    assert_eq!(*resolve(&by_id, &aliases, "creds").unwrap(), "provider-a");
    assert_eq!(*resolve(&by_id, &aliases, "security.credentials").unwrap(), "provider-a");
    assert_eq!(
        resolve(&by_id, &aliases, "unknown.provider"),
        Err(RegistryError::UnknownProvider { id: "unknown.provider".to_string() })
    );
}

#[test]
fn registry_select_filters_out_non_selectable_providers() {
    let mut by_id = BTreeMap::new();
    by_id.insert("a".to_string(), (1, true));
    by_id.insert("b".to_string(), (2, false));
    let aliases = BTreeMap::new();

    let selected = select(&by_id, &aliases, &["a".to_string(), "b".to_string()], |(_, selectable)| *selectable).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0], &(1, true));
}

#[test]
fn registry_select_propagates_unknown_provider_error() {
    let by_id: BTreeMap<String, bool> = BTreeMap::new();
    let aliases = BTreeMap::new();
    let err = select(&by_id, &aliases, &["ghost".to_string()], |_| true);
    assert_eq!(err, Err(RegistryError::UnknownProvider { id: "ghost".to_string() }));
}
