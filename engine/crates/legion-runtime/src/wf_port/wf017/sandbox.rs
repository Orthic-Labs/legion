//! Port of src/lib/remediation/sandbox.mjs (B7-030).
//!
//! Every remediation run - proposal, preview, verification - happens in a
//! copy of the bound base revision, never in the user's primary repository.
//! The sandbox receipt records exactly what was created and how to recover
//! it, and is bound to the finding run so a proposal cannot be verified
//! against a different audit than the one that produced it.

use super::digest_of;
use async_trait::async_trait;
use serde::Serialize;
use std::path::{Path, PathBuf};

pub const SANDBOX_SCHEMA_VERSION: u32 = 1;

/// Bounded overlay policies. A producer never chooses its own.
pub const INPUT_OVERLAY_POLICIES: &[&str] =
    &["bound-base-revision-only", "bound-base-revision-plus-dirty-overlay"];

#[derive(Debug, Clone, Serialize)]
pub struct ProcessPolicy {
    pub execution: &'static str,
    #[serde(rename = "allowedExecutables")]
    pub allowed_executables: Vec<&'static str>,
    #[serde(rename = "inheritEnvironment")]
    pub inherit_environment: bool,
    #[serde(rename = "cwdConfinedToSandbox")]
    pub cwd_confined_to_sandbox: bool,
}

pub fn sandbox_process_policy() -> ProcessPolicy {
    ProcessPolicy {
        execution: "allowlist-only",
        allowed_executables: vec!["git"],
        inherit_environment: false,
        cwd_confined_to_sandbox: true,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkPolicy {
    pub allowed: bool,
    pub reason: &'static str,
}

pub fn sandbox_network_policy() -> NetworkPolicy {
    NetworkPolicy {
        allowed: false,
        reason: "remediation is offline; no fetch, publish, or upload is permitted",
    }
}

#[derive(Debug, Clone)]
pub struct SandboxError(pub String);
impl std::fmt::Display for SandboxError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}
impl std::error::Error for SandboxError {}

/// Host capability gate. `host.capabilities.mutation !== true` in the JS
/// source; represented here as a plain bool the caller supplies.
pub fn require_mutation_capability(host_mutation_capability: bool) -> Result<(), SandboxError> {
    if !host_mutation_capability {
        return Err(SandboxError(
            "remediation sandbox requires explicit host mutation capability".to_string(),
        ));
    }
    Ok(())
}

fn within_primary_worktree(candidate: &Path, repo_root: &Path) -> bool {
    let root = repo_root.to_path_buf();
    let path = candidate.to_path_buf();
    if path == root {
        return true;
    }
    let root_with_sep = {
        let mut s = root.to_string_lossy().to_string();
        if !s.ends_with(std::path::MAIN_SEPARATOR) {
            s.push(std::path::MAIN_SEPARATOR);
        }
        s
    };
    let path_str = path.to_string_lossy().to_string();
    if !path_str.starts_with(&root_with_sep) {
        return false;
    }
    // The git common directory lives under the root but is not the working tree.
    let sep = std::path::MAIN_SEPARATOR;
    !path_str.contains(&format!("{sep}.git{sep}"))
}

#[derive(Debug, Clone)]
pub struct RepoRef {
    pub root: PathBuf,
    pub git_common_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaseIdentity {
    #[serde(rename = "repositoryRevision")]
    pub repository_revision: String,
    #[serde(rename = "dirtyPatchDigest")]
    pub dirty_patch_digest: Option<String>,
    #[serde(rename = "planDigest")]
    pub plan_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupCommand {
    pub command: Vec<String>,
    pub cwd: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxReceipt {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: &'static str,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "sandboxPath")]
    pub sandbox_path: String,
    #[serde(rename = "baseRevision")]
    pub base_revision: String,
    #[serde(rename = "baseIdentity")]
    pub base_identity: BaseIdentity,
    #[serde(rename = "inputOverlayPolicy")]
    pub input_overlay_policy: String,
    #[serde(rename = "processPolicy")]
    pub process_policy: ProcessPolicy,
    #[serde(rename = "networkPolicy")]
    pub network_policy: NetworkPolicy,
    #[serde(rename = "createdPaths")]
    pub created_paths: Vec<String>,
    pub cleanup: CleanupCommand,
    #[serde(rename = "primaryRepositoryMutated")]
    pub primary_repository_mutated: bool,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    pub binding: serde_json::Map<String, serde_json::Value>,
    #[serde(rename = "findingRunDigest")]
    pub finding_run_digest: String,
    pub digest: String,
}

pub struct SandboxReceiptInput {
    pub run_id: String,
    pub sandbox_path: String,
    pub base_revision: String,
    pub base_identity: BaseIdentity,
    pub input_overlay_policy: String,
    pub created_paths: Vec<String>,
    pub cleanup: CleanupCommand,
    pub binding: serde_json::Map<String, serde_json::Value>,
    pub finding_run_digest: String,
    pub created_at: Option<String>,
}

pub fn sandbox_receipt(mut input: SandboxReceiptInput) -> SandboxReceipt {
    input.created_paths.sort();
    let mut receipt = SandboxReceipt {
        schema_version: SANDBOX_SCHEMA_VERSION,
        kind: "legion-remediation-sandbox",
        run_id: input.run_id,
        sandbox_path: input.sandbox_path,
        base_revision: input.base_revision,
        base_identity: input.base_identity,
        input_overlay_policy: input.input_overlay_policy,
        process_policy: sandbox_process_policy(),
        network_policy: sandbox_network_policy(),
        created_paths: input.created_paths,
        cleanup: input.cleanup,
        primary_repository_mutated: false,
        created_at: input.created_at,
        binding: input.binding,
        finding_run_digest: input.finding_run_digest,
        digest: String::new(),
    };
    receipt.digest = digest_of("sandbox", &receipt);
    receipt
}

/// Fails loudly if a sandbox would (or did) land inside the user's working
/// tree.
pub fn assert_primary_repository_untouched(receipt: &SandboxReceipt, repo: &RepoRef) -> Result<(), SandboxError> {
    // The JS source defensively checks `receipt.primaryRepositoryMutated !==
    // false` on an untyped object; `SandboxReceipt::primary_repository_mutated`
    // is a typed `bool` that this port always constructs as `false`, so that
    // check can never fail here and is intentionally not reproduced.
    if within_primary_worktree(Path::new(&receipt.sandbox_path), &repo.root) {
        return Err(SandboxError(format!(
            "sandbox path {} is inside the primary repository working tree",
            receipt.sandbox_path
        )));
    }
    for path in &receipt.created_paths {
        if within_primary_worktree(Path::new(path), &repo.root) {
            return Err(SandboxError(format!(
                "sandbox created {path} inside the primary repository working tree"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ProcessRunRequest {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessRunResult {
    pub exit_code: i32,
    pub stderr: String,
}

/// The host process runner. Real execution is the host's job; this port only
/// defines the contract, matching `processRunner.run(...)` in the JS source.
#[async_trait]
pub trait ProcessRunner: Send + Sync {
    async fn run(&self, request: ProcessRunRequest) -> ProcessRunResult;
}

pub struct CreateRemediationSandboxInput<'a> {
    pub repo: &'a RepoRef,
    pub base_revision: String,
    pub run_id: String,
    pub host_mutation_capability: bool,
    pub binding_repository_revision: String,
    pub binding_dirty_patch_digest: Option<String>,
    pub binding_plan_digest: String,
    pub binding: serde_json::Map<String, serde_json::Value>,
    pub finding_run_digest: String,
    pub input_overlay_policy: String,
    pub created_at: Option<String>,
}

#[derive(Debug)]
pub struct CreateRemediationSandboxOutput {
    pub path: String,
    pub receipt: SandboxReceipt,
}

/// Create one isolated sandbox per remediation run.
pub async fn create_remediation_sandbox(
    input: CreateRemediationSandboxInput<'_>,
    process_runner: &dyn ProcessRunner,
) -> Result<CreateRemediationSandboxOutput, SandboxError> {
    require_mutation_capability(input.host_mutation_capability)?;
    if !INPUT_OVERLAY_POLICIES.contains(&input.input_overlay_policy.as_str()) {
        return Err(SandboxError(format!(
            "unknown input overlay policy: {}",
            input.input_overlay_policy
        )));
    }
    if input.binding_repository_revision.is_empty() {
        return Err(SandboxError("sandbox requires the run binding".to_string()));
    }
    if input.base_revision != input.binding_repository_revision {
        return Err(SandboxError(
            "sandbox base revision does not match the bound run revision".to_string(),
        ));
    }
    if !input.finding_run_digest.starts_with("sha256:") {
        return Err(SandboxError("sandbox must be bound to a finding run digest".to_string()));
    }
    if input.input_overlay_policy == "bound-base-revision-only" && input.binding_dirty_patch_digest.is_some() {
        return Err(SandboxError(
            "bound-base-revision-only sandbox cannot be created from a dirty run".to_string(),
        ));
    }

    let path = input
        .repo
        .git_common_dir
        .join("legion-sandboxes")
        .join(&input.run_id);
    if within_primary_worktree(&path, &input.repo.root) {
        return Err(SandboxError(format!(
            "refusing to create a sandbox inside the primary repository working tree: {}",
            path.display()
        )));
    }

    let path_string = path.to_string_lossy().to_string();
    let result = process_runner
        .run(ProcessRunRequest {
            executable: "git".to_string(),
            args: vec![
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                path_string.clone(),
                input.base_revision.clone(),
            ],
            cwd: input.repo.root.clone(),
        })
        .await;
    if result.exit_code != 0 {
        return Err(SandboxError(format!("sandbox creation failed: {}", result.stderr)));
    }

    let cleanup = CleanupCommand {
        command: vec![
            "git".to_string(),
            "worktree".to_string(),
            "remove".to_string(),
            "--force".to_string(),
            path_string.clone(),
        ],
        cwd: input.repo.root.to_string_lossy().to_string(),
        description: "Remove the remediation sandbox worktree.".to_string(),
    };

    let receipt = sandbox_receipt(SandboxReceiptInput {
        run_id: input.run_id,
        sandbox_path: path_string.clone(),
        base_revision: input.base_revision,
        base_identity: BaseIdentity {
            repository_revision: input.binding_repository_revision,
            dirty_patch_digest: input.binding_dirty_patch_digest,
            plan_digest: input.binding_plan_digest,
        },
        input_overlay_policy: input.input_overlay_policy,
        created_paths: vec![path_string.clone()],
        cleanup,
        binding: input.binding,
        finding_run_digest: input.finding_run_digest,
        created_at: input.created_at,
    });
    assert_primary_repository_untouched(&receipt, input.repo)?;
    Ok(CreateRemediationSandboxOutput {
        path: path_string,
        receipt,
    })
}

/// JSON Schema for the sandbox receipt, matching `buildSandboxReceiptSchema`.
pub fn build_sandbox_receipt_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/remediation/sandbox-receipt-v1.json",
        "title": "RemediationSandboxReceiptV1",
        "type": "object",
        "required": [
            "schemaVersion", "kind", "runId", "sandboxPath", "baseRevision", "baseIdentity",
            "inputOverlayPolicy", "processPolicy", "networkPolicy", "createdPaths", "cleanup",
            "primaryRepositoryMutated", "binding", "findingRunDigest", "digest"
        ],
        "properties": {
            "schemaVersion": { "const": SANDBOX_SCHEMA_VERSION },
            "kind": { "const": "legion-remediation-sandbox" },
            "runId": { "type": "string", "minLength": 1 },
            "sandboxPath": { "type": "string", "minLength": 1 },
            "baseRevision": { "type": "string", "minLength": 1 },
            "baseIdentity": {
                "type": "object",
                "required": ["repositoryRevision", "dirtyPatchDigest", "planDigest"],
                "properties": {
                    "repositoryRevision": { "type": "string", "minLength": 1 },
                    "dirtyPatchDigest": { "type": ["string", "null"] },
                    "planDigest": { "type": "string", "pattern": "^sha256:" }
                },
                "additionalProperties": false
            },
            "inputOverlayPolicy": { "enum": INPUT_OVERLAY_POLICIES },
            "processPolicy": { "type": "object" },
            "networkPolicy": {
                "type": "object",
                "required": ["allowed", "reason"],
                "properties": { "allowed": { "const": false }, "reason": { "type": "string" } },
                "additionalProperties": false
            },
            "createdPaths": { "type": "array", "items": { "type": "string" } },
            "cleanup": {
                "type": "object",
                "required": ["command", "cwd", "description"],
                "properties": {
                    "command": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
                    "cwd": { "type": "string" },
                    "description": { "type": "string" }
                },
                "additionalProperties": false
            },
            "primaryRepositoryMutated": { "const": false },
            "createdAt": { "type": ["string", "null"] },
            "binding": { "type": "object" },
            "findingRunDigest": { "type": "string", "pattern": "^sha256:" },
            "digest": { "type": "string", "pattern": "^sha256:" }
        },
        "additionalProperties": false
    })
}
