//! Port of `src/lib/remediation/{agent-patch,apply,checkpoint,cleanup,code-proposal}.mjs`
//! (chunk wf015).
//!
//! Legion never mutates a repository from inside this engine: `apply` gates on
//! an explicit host mutation capability, a valid neutral verification, and a
//! matching target fingerprint, then hands the patch to a host-supplied
//! mutator. No filesystem or process-spawn API is imported by the pure parts
//! of this module; `restore_checkpoint` and `cleanup_sandbox` take a
//! `ProcessRunner` trait object supplied by the caller instead of shelling out
//! themselves, mirroring the JS modules' injected `processRunner`.
//!
//! `fixProposal` (`src/lib/remediation/fix-contract.mjs`) and
//! `reasoningProposal` (`src/lib/remediation/reasoning-packets.mjs`) are not in
//! this chunk's file list. `agent_patch_proposal` and `code_proposal` need
//! their shape, so this module carries small local ports of exactly the
//! pieces it depends on (`local_fix_proposal`, `local_reasoning_proposal`).
//! When the chunk that owns `fix-contract.mjs`/`reasoning-packets.mjs` lands
//! its own port, the integrator should re-point these two functions at the
//! canonical implementation and delete the local copies here.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Shared digest helper — port of the `sha256:${createHash('sha256')...}`
// pattern used throughout every one of these modules.
// ---------------------------------------------------------------------------

fn sha256_of(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Digest of a bare JSON value with no namespace prefix (port of the
/// `JSON.stringify` + sha256 calls that omit a namespace, e.g. `digestOf` in
/// `fix-contract.mjs`'s `body.id` line).
fn sha256_plain(value: &Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut out = values.to_vec();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// checkpoint.mjs
// ---------------------------------------------------------------------------

/// Port of `checkpointDigest` in `checkpoint.mjs`.
pub fn checkpoint_digest(state: &Value) -> String {
    sha256_of("checkpoint", state)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "worktreePath")]
    pub worktree_path: String,
    #[serde(rename = "baseCommit")]
    pub base_commit: String,
    pub files: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    pub digest: String,
}

/// Port of `createCheckpoint` in `checkpoint.mjs`.
pub fn create_checkpoint(worktree_path: &str, base_commit: &str, files: &[String]) -> Checkpoint {
    let sorted_files = sorted_strings(files);
    // Mirror the JS object's field order exactly (digest is appended after
    // the body is built, and is NOT part of the digested value itself,
    // because `createdAt` is always `null` at construction time).
    let body = json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-checkpoint",
        "worktreePath": worktree_path,
        "baseCommit": base_commit,
        "files": sorted_files,
        "createdAt": Value::Null,
    });
    let digest = checkpoint_digest(&body);
    Checkpoint {
        schema_version: 1,
        kind: "legion-remediation-checkpoint".to_string(),
        worktree_path: worktree_path.to_string(),
        base_commit: base_commit.to_string(),
        files: sorted_files,
        created_at: None,
        digest,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreStep {
    pub file: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestorePlan {
    pub kind: String,
    #[serde(rename = "checkpointDigest")]
    pub checkpoint_digest: String,
    pub steps: Vec<RestoreStep>,
    #[serde(rename = "recoveryCommand")]
    pub recovery_command: String,
}

/// Port of `restorePlan` in `checkpoint.mjs`.
pub fn restore_plan(checkpoint: &Checkpoint) -> RestorePlan {
    let steps: Vec<RestoreStep> = checkpoint
        .files
        .iter()
        .map(|file| RestoreStep {
            file: file.clone(),
            action: "revert-to-base".to_string(),
        })
        .collect();
    let recovery_command = format!(
        "git -C {} checkout -- {}",
        checkpoint.worktree_path,
        checkpoint.files.join(" ")
    );
    RestorePlan {
        kind: "legion-checkpoint-restore".to_string(),
        checkpoint_digest: checkpoint.digest.clone(),
        steps,
        recovery_command,
    }
}

/// The subset of a spawned process's outcome these modules need. A port of
/// the ad hoc `{ exitCode, stderr, error }` shape the JS `processRunner`
/// contract returns.
#[derive(Debug, Clone, Default)]
pub struct ProcessOutcome {
    pub exit_code: i32,
    pub stderr: Option<String>,
}

/// Port of the injected `processRunner.run(spec)` contract. Implementations
/// live with the host (test doubles, or a real spawner) — this crate never
/// spawns a process on its own.
pub trait ProcessRunner {
    fn run<'a>(
        &'a self,
        executable: &'a str,
        args: &'a [String],
        cwd: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = ProcessOutcome> + Send + 'a>>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointRestoreReceipt {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "checkpointDigest")]
    pub checkpoint_digest: String,
    #[serde(rename = "worktreePath")]
    pub worktree_path: String,
    pub files: Vec<String>,
    pub restored: bool,
    pub error: Option<String>,
    #[serde(rename = "recoveryCommand")]
    pub recovery_command: String,
}

/// Port of `restoreCheckpoint` in `checkpoint.mjs`.
pub async fn restore_checkpoint(
    checkpoint: &Checkpoint,
    runner: &dyn ProcessRunner,
) -> CheckpointRestoreReceipt {
    let plan = restore_plan(checkpoint);
    let files: Vec<String> = plan.steps.iter().map(|s| s.file.clone()).collect();
    let (restored, error) = if files.is_empty() {
        (true, None)
    } else {
        let mut args: Vec<String> = vec![
            "-C".to_string(),
            checkpoint.worktree_path.clone(),
            "checkout".to_string(),
            "--".to_string(),
        ];
        args.extend(files.iter().cloned());
        let outcome = runner
            .run("git", &args, Some(checkpoint.worktree_path.as_str()))
            .await;
        let restored = outcome.exit_code == 0;
        let error = if restored {
            None
        } else {
            Some(outcome.stderr.unwrap_or_else(|| "unknown".to_string()))
        };
        (restored, error)
    };
    CheckpointRestoreReceipt {
        schema_version: 1,
        kind: "legion-checkpoint-restore-receipt".to_string(),
        checkpoint_digest: checkpoint.digest.clone(),
        worktree_path: checkpoint.worktree_path.clone(),
        files,
        restored,
        error,
        recovery_command: plan.recovery_command,
    }
}

// ---------------------------------------------------------------------------
// cleanup.mjs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupReceipt {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    pub path: String,
    pub removed: bool,
    pub error: Option<String>,
    #[serde(rename = "residualPaths")]
    pub residual_paths: Vec<String>,
    #[serde(rename = "recoveryCommand")]
    pub recovery_command: Option<Vec<String>>,
}

/// Port of `cleanupReceipt` in `cleanup.mjs`. `error`/`recovery_command`
/// default to the JS defaults (`'unknown'` / `['git', 'worktree', 'remove',
/// '--force', path]`) when `removed` is `false` and the caller passes `None`.
pub fn cleanup_receipt(
    path: &str,
    removed: bool,
    error: Option<String>,
    recovery_command: Option<Vec<String>>,
    residual_paths: Option<Vec<String>>,
) -> CleanupReceipt {
    CleanupReceipt {
        schema_version: 1,
        kind: "legion-remediation-cleanup".to_string(),
        path: path.to_string(),
        removed,
        error: if removed {
            None
        } else {
            Some(error.unwrap_or_else(|| "unknown".to_string()))
        },
        residual_paths: if removed {
            Vec::new()
        } else {
            residual_paths.unwrap_or_else(|| vec![path.to_string()])
        },
        recovery_command: if removed {
            None
        } else {
            Some(recovery_command.unwrap_or_else(|| {
                vec![
                    "git".to_string(),
                    "worktree".to_string(),
                    "remove".to_string(),
                    "--force".to_string(),
                    path.to_string(),
                ]
            }))
        },
    }
}

/// Minimal port of the `sandbox` shape `cleanupSandbox` reads in `cleanup.mjs`.
#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    pub sandbox_path: Option<String>,
    pub cleanup_command: Option<Vec<String>>,
    pub cleanup_cwd: Option<String>,
    pub created_paths: Vec<String>,
}

/// Port of `cleanupSandbox` in `cleanup.mjs`.
pub async fn cleanup_sandbox(sandbox: &Sandbox, runner: &dyn ProcessRunner) -> CleanupReceipt {
    let default_path = sandbox.sandbox_path.clone().unwrap_or_default();
    let command = sandbox.cleanup_command.clone().unwrap_or_else(|| {
        vec![
            "git".to_string(),
            "worktree".to_string(),
            "remove".to_string(),
            "--force".to_string(),
            default_path.clone(),
        ]
    });
    let (executable, args) = match command.split_first() {
        Some((exe, rest)) => (exe.clone(), rest.to_vec()),
        None => ("git".to_string(), Vec::new()),
    };
    let outcome = runner
        .run(&executable, &args, sandbox.cleanup_cwd.as_deref())
        .await;
    let removed = outcome.exit_code == 0;

    let mut residual: Vec<String> = vec![default_path.clone()];
    residual.extend(sandbox.created_paths.iter().cloned());
    let mut seen = std::collections::BTreeSet::new();
    let mut residual_paths: Vec<String> = residual
        .into_iter()
        .filter(|p| seen.insert(p.clone()))
        .collect();
    residual_paths.sort();

    cleanup_receipt(
        &default_path,
        removed,
        if removed {
            None
        } else {
            Some(outcome.stderr.unwrap_or_else(|| "unknown".to_string()))
        },
        if removed { None } else { Some(command) },
        if removed { None } else { Some(residual_paths) },
    )
}

// ---------------------------------------------------------------------------
// apply.mjs
// ---------------------------------------------------------------------------

pub const APPLY_RECEIPT_SCHEMA_VERSION: u32 = 1;

/// Port of `treeFingerprint` in `apply.mjs`.
pub fn tree_fingerprint(files: &[String]) -> String {
    let sorted = sorted_strings(files);
    let body = serde_json::to_string(&sorted).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"tree-fingerprint\0");
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Port of `requireApplyCapability` in `apply.mjs`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApplyError {
    #[error("apply requires explicit host mutation capability")]
    MissingMutationCapability,
    #[error("apply requires a valid neutral verification for this proposal")]
    InvalidVerification,
    #[error("the verification does not belong to this proposal")]
    VerificationProposalMismatch,
    #[error("producer must not verify its own proposal")]
    ProducerIsVerifier,
    #[error("target repository fingerprint changed since verification; refusing to apply on stale identity")]
    StaleFingerprint,
}

pub struct HostCapabilities {
    pub mutation: bool,
}

/// Port of `requireApplyCapability` in `apply.mjs`.
pub fn require_apply_capability(host: &HostCapabilities) -> Result<(), ApplyError> {
    if !host.mutation {
        return Err(ApplyError::MissingMutationCapability);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: String,
    pub target_paths: Vec<String>,
    pub finding_ids: Vec<String>,
    pub patch_digest: Option<String>,
    pub producer_identity: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Verification {
    pub kind: String,
    pub valid: bool,
    pub proposal_id: String,
    pub digest: Option<String>,
    pub verifier_identity: Option<String>,
}

/// Port of `requireValidVerification` in `apply.mjs`, including its call into
/// `assertProducerIsNotVerifier` (`reasoning-packets.mjs`; not in this
/// chunk's file list, so ported inline as the identity-equality check the JS
/// helper performs).
fn require_valid_verification(
    proposal: &Proposal,
    verification: &Verification,
) -> Result<(), ApplyError> {
    if verification.kind != "legion-remediation-verification" || !verification.valid {
        return Err(ApplyError::InvalidVerification);
    }
    if verification.proposal_id != proposal.id {
        return Err(ApplyError::VerificationProposalMismatch);
    }
    if proposal.producer_identity.is_some()
        && proposal.producer_identity == verification.verifier_identity
    {
        return Err(ApplyError::ProducerIsVerifier);
    }
    Ok(())
}

/// Port of the host `mutator.apply(...)` result shape.
#[derive(Debug, Clone, Default)]
pub struct MutatorResult {
    pub ok: bool,
    pub fingerprint: Option<String>,
    pub reverse_patch_digest: Option<String>,
    pub error: Option<String>,
}

/// Port of the host-supplied `mutator` contract in `apply.mjs`.
#[async_trait::async_trait]
pub trait Mutator {
    async fn apply(
        &self,
        proposal_id: &str,
        patch_digest: Option<&str>,
        target_paths: &[String],
        expected_fingerprint: &str,
    ) -> MutatorResult;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryInfo {
    pub command: Option<Vec<String>>,
    pub description: String,
}

// NB: no `Eq` derive — `binding: Value` is not `Eq` (serde_json::Value wraps
// `f64`, which has no total order).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplyReceiptV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "proposalId")]
    pub proposal_id: String,
    #[serde(rename = "findingIds")]
    pub finding_ids: Vec<String>,
    #[serde(rename = "patchDigest")]
    pub patch_digest: Option<String>,
    #[serde(rename = "verificationDigest")]
    pub verification_digest: Option<String>,
    #[serde(rename = "appliedBy")]
    pub applied_by: String,
    pub applied: bool,
    #[serde(rename = "beforeFingerprint")]
    pub before_fingerprint: String,
    #[serde(rename = "afterFingerprint")]
    pub after_fingerprint: Option<String>,
    #[serde(rename = "observedFingerprint")]
    pub observed_fingerprint: Option<String>,
    #[serde(rename = "reversePatchDigest")]
    pub reverse_patch_digest: Option<String>,
    pub error: Option<String>,
    pub recoverable: bool,
    pub recovery: RecoveryInfo,
    #[serde(rename = "rolledBack")]
    pub rolled_back: bool,
    pub binding: Value,
    pub digest: String,
}

/// Port of `applyProposal` in `apply.mjs`.
pub async fn apply_proposal(
    proposal: &Proposal,
    verification: &Verification,
    host: &HostCapabilities,
    mutator: &dyn Mutator,
    target_fingerprint: &str,
    observed_fingerprint: &str,
    binding: Value,
) -> Result<ApplyReceiptV2, ApplyError> {
    require_apply_capability(host)?;
    require_valid_verification(proposal, verification)?;
    if observed_fingerprint != target_fingerprint {
        return Err(ApplyError::StaleFingerprint);
    }

    let sorted_targets = sorted_strings(&proposal.target_paths);
    let result = mutator
        .apply(
            &proposal.id,
            proposal.patch_digest.as_deref(),
            &sorted_targets,
            target_fingerprint,
        )
        .await;

    let applied = result.ok;
    let after_fingerprint = if applied {
        result.fingerprint.clone()
    } else {
        None
    };
    let observed = if applied {
        result.fingerprint.clone()
    } else {
        Some(
            result
                .fingerprint
                .clone()
                .unwrap_or_else(|| target_fingerprint.to_string()),
        )
    };
    let recoverable = if applied {
        true
    } else {
        result
            .fingerprint
            .clone()
            .unwrap_or_else(|| target_fingerprint.to_string())
            == target_fingerprint
    };
    let recovery = if applied {
        RecoveryInfo {
            command: None,
            description: "rollback via the reverse patch or the sandbox checkpoint".to_string(),
        }
    } else {
        RecoveryInfo {
            command: Some(vec![
                "legion".to_string(),
                "remediation".to_string(),
                "rollback".to_string(),
                "--proposal".to_string(),
                proposal.id.clone(),
            ]),
            description: "restore the pre-apply fingerprint through the host mutator".to_string(),
        }
    };

    let sorted_findings = sorted_strings(&proposal.finding_ids);
    let body = json!({
        "schemaVersion": APPLY_RECEIPT_SCHEMA_VERSION,
        "kind": "legion-remediation-apply-receipt",
        "proposalId": proposal.id.clone(),
        "findingIds": sorted_findings.clone(),
        "patchDigest": proposal.patch_digest.clone(),
        "verificationDigest": verification.digest.clone(),
        "appliedBy": "host-mutator",
        "applied": applied,
        "beforeFingerprint": target_fingerprint,
        "afterFingerprint": after_fingerprint.clone(),
        "observedFingerprint": observed.clone(),
        "reversePatchDigest": if applied { result.reverse_patch_digest.clone() } else { None },
        "error": if applied { None } else { Some(result.error.clone().unwrap_or_else(|| "unknown".to_string())) },
        "recoverable": recoverable,
        "recovery": { "command": recovery.command.clone(), "description": recovery.description.clone() },
        "rolledBack": false,
        "binding": binding,
    });
    let digest = sha256_plain(&body);

    Ok(ApplyReceiptV2 {
        schema_version: APPLY_RECEIPT_SCHEMA_VERSION,
        kind: "legion-remediation-apply-receipt".to_string(),
        proposal_id: proposal.id.clone(),
        finding_ids: sorted_findings,
        patch_digest: proposal.patch_digest.clone(),
        verification_digest: verification.digest.clone(),
        applied_by: "host-mutator".to_string(),
        applied,
        before_fingerprint: target_fingerprint.to_string(),
        after_fingerprint,
        observed_fingerprint: observed,
        reverse_patch_digest: if applied {
            result.reverse_patch_digest
        } else {
            None
        },
        error: if applied {
            None
        } else {
            Some(result.error.unwrap_or_else(|| "unknown".to_string()))
        },
        recoverable,
        recovery,
        rolled_back: false,
        binding: body["binding"].clone(),
        digest,
    })
}

// -- Pre-existing helpers retained for their existing callers (bottom of apply.mjs) --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplyReceipt {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "proposalId")]
    pub proposal_id: String,
    #[serde(rename = "patchDigest")]
    pub patch_digest: String,
    #[serde(rename = "worktreePath")]
    pub worktree_path: String,
    #[serde(rename = "beforeFingerprint")]
    pub before_fingerprint: String,
    #[serde(rename = "afterFingerprint")]
    pub after_fingerprint: String,
    pub applied: bool,
    #[serde(rename = "rolledBack")]
    pub rolled_back: bool,
}

/// Port of `applyReceipt` in `apply.mjs`.
pub fn apply_receipt(
    proposal_id: &str,
    patch_digest: &str,
    worktree_path: &str,
    before_fingerprint: &str,
    after_fingerprint: &str,
    applied: bool,
) -> ApplyReceipt {
    ApplyReceipt {
        schema_version: 1,
        kind: "legion-patch-apply".to_string(),
        proposal_id: proposal_id.to_string(),
        patch_digest: patch_digest.to_string(),
        worktree_path: worktree_path.to_string(),
        before_fingerprint: before_fingerprint.to_string(),
        after_fingerprint: after_fingerprint.to_string(),
        applied,
        rolled_back: false,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackReceipt {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "applyDigest")]
    pub apply_digest: Option<String>,
    #[serde(rename = "reversePatchDigest")]
    pub reverse_patch_digest: String,
    #[serde(rename = "restoredFingerprint")]
    pub restored_fingerprint: String,
    #[serde(rename = "worktreePath")]
    pub worktree_path: String,
    pub restored: bool,
}

/// Port of `rollbackReceipt` in `apply.mjs`. `apply` is `None` when the JS
/// caller passes `undefined`/`null` (its `apply?.patchDigest` and
/// `apply?.beforeFingerprint` then read as `null`/`undefined`, and
/// `restoredFingerprint === undefined` is always `false`).
pub fn rollback_receipt(
    apply: Option<&ApplyReceipt>,
    reverse_patch_digest: &str,
    restored_fingerprint: &str,
    worktree_path: &str,
) -> RollbackReceipt {
    let apply_digest = apply.map(|a| a.patch_digest.clone());
    let restored = match apply {
        Some(a) => restored_fingerprint == a.before_fingerprint,
        None => false,
    };
    RollbackReceipt {
        schema_version: 1,
        kind: "legion-patch-rollback".to_string(),
        apply_digest,
        reverse_patch_digest: reverse_patch_digest.to_string(),
        restored_fingerprint: restored_fingerprint.to_string(),
        worktree_path: worktree_path.to_string(),
        restored,
    }
}

// ---------------------------------------------------------------------------
// Local ports of the `fix-contract.mjs` / `reasoning-packets.mjs` pieces that
// `agent-patch.mjs` and `code-proposal.mjs` depend on. See the module doc
// comment: these are NOT this chunk's files to own long-term.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PatchInfo {
    pub path: String,
    pub digest: Option<String>,
}

/// Local port of `fixProposal` in `fix-contract.mjs`, only as far as
/// `agentPatchProposal` in `agent-patch.mjs` needs it.
fn local_fix_proposal(
    finding_id: &str,
    root_cause_digest: Option<&str>,
    producer: Value,
    target_paths: &[String],
    preconditions: &[String],
    patch: Value,
    expected_behavior: &[String],
    risks: &[String],
    validation_commands: &[String],
    tier: &str,
) -> Value {
    let mut body = Map::new();
    body.insert("schemaVersion".to_string(), json!(1));
    body.insert("kind".to_string(), json!("legion-fix-proposal"));
    body.insert("findingId".to_string(), json!(finding_id));
    body.insert("rootCauseDigest".to_string(), json!(root_cause_digest));
    body.insert("producer".to_string(), producer);
    body.insert("targetPaths".to_string(), json!(sorted_strings(target_paths)));
    body.insert(
        "preconditions".to_string(),
        json!(sorted_strings(preconditions)),
    );
    body.insert("patch".to_string(), patch);
    body.insert(
        "expectedBehavior".to_string(),
        json!(sorted_strings(expected_behavior)),
    );
    body.insert("risks".to_string(), json!(sorted_strings(risks)));
    body.insert(
        "validationCommands".to_string(),
        json!(sorted_strings(validation_commands)),
    );
    body.insert("tier".to_string(), json!(tier));
    let value = Value::Object(body.clone());
    let id = sha256_plain(&value);
    body.insert("id".to_string(), json!(id));
    Value::Object(body)
}

/// Port of `agentPatchPacket` in `agent-patch.mjs`.
pub fn agent_patch_packet(
    finding_id: &str,
    root_cause_digest: Option<&str>,
    worktree_path: &str,
    scope: &[String],
    max_batches: Option<u32>,
) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-agent-patch-packet",
        "findingId": finding_id,
        "rootCauseDigest": root_cause_digest,
        "worktreePath": worktree_path,
        "scope": sorted_strings(scope),
        "maxBatches": max_batches.unwrap_or(4),
        "bounded": true,
        "verification": "performed by neutral verification after the packet returns",
    })
}

/// Port of `agentPatchProposal` in `agent-patch.mjs`.
pub fn agent_patch_proposal(
    finding_id: &str,
    root_cause_digest: Option<&str>,
    packet_id: Option<&str>,
    model_identity: Option<&str>,
    patch: &PatchInfo,
    expected_behavior: &[String],
    risks: &[String],
    validation_commands: &[String],
) -> Value {
    local_fix_proposal(
        finding_id,
        root_cause_digest,
        json!({
            "kind": "agent-guided",
            "packetId": packet_id,
            "modelIdentity": model_identity,
        }),
        &[],
        &[
            "packet is bounded".to_string(),
            "worktree is isolated".to_string(),
            "scope grant is explicit".to_string(),
        ],
        json!({ "path": patch.path.clone(), "digest": patch.digest.clone() }),
        expected_behavior,
        risks,
        validation_commands,
        "AGENT_GUIDED",
    )
}

/// Local port of `reasoningProposal` in `reasoning-packets.mjs`, only as far
/// as `codeProposal` in `code-proposal.mjs` needs it: it stamps a
/// packet-scoped, owner-scoped envelope around the caller's `extra` fields.
fn local_reasoning_proposal(packet: &Value, owner: &str, changes: &Value, binding: &Value, extra: Map<String, Value>) -> Value {
    let mut body = Map::new();
    body.insert("schemaVersion".to_string(), json!(1));
    body.insert("kind".to_string(), json!("legion-remediation-proposal"));
    body.insert("owner".to_string(), json!(owner));
    body.insert(
        "packetId".to_string(),
        packet.get("packetId").cloned().unwrap_or(Value::Null),
    );
    body.insert("changes".to_string(), changes.clone());
    body.insert("binding".to_string(), binding.clone());
    for (key, value) in extra {
        body.insert(key, value);
    }
    let value = Value::Object(body.clone());
    let id = sha256_plain(&value);
    body.insert("id".to_string(), json!(id));
    Value::Object(body)
}

/// Port of `codeProposal` in `code-proposal.mjs`.
pub fn code_proposal(packet: &Value, changes: &[Value], binding: &Value) -> Value {
    let patch = changes
        .iter()
        .find(|change| change.get("patch").is_some())
        .and_then(|change| change.get("patch").cloned())
        .unwrap_or(Value::Null);

    let mut extra = Map::new();
    extra.insert(
        "expectedBehavior".to_string(),
        json!(["the finding no longer reproduces and no unrelated behavior changes"]),
    );
    extra.insert(
        "affectedFamilies".to_string(),
        json!(["security", "code"]),
    );
    extra.insert(
        "validationPlan".to_string(),
        json!(["parse-check", "affected-provider-rerun", "baseline-gate-recheck"]),
    );
    extra.insert("patch".to_string(), patch);

    local_reasoning_proposal(packet, "code", &Value::Array(changes.to_vec()), binding, extra)
}
