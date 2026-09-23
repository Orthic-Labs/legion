//! Port of `src/lib/remediation/{verify-proposal,worktree,writing-proposal}.mjs`
//! (chunk wf018).
//!
//! `verify-proposal.mjs` and `writing-proposal.mjs` both depend on
//! `src/lib/remediation/reasoning-packets.mjs`
//! (`assertProducerIsNotVerifier`, `assertOwnerAuthority`, `reasoningProposal`,
//! `assertPathAllowed`) and `verify-proposal.mjs` also depends on
//! `src/lib/remediation/effect-graph.mjs` (`blocksAutoApply`). Neither of
//! those two files is in this chunk's file list, so — mirroring the approach
//! already used by `wf_port::wf015` for `fix-contract.mjs` /
//! `reasoning-packets.mjs` — this module carries small local ports of exactly
//! the pieces it depends on (`local_assert_owner`, `local_assert_owner_authority`,
//! `local_assert_producer_is_not_verifier`, `local_assert_path_allowed`,
//! `local_reasoning_proposal`, `local_blocks_auto_apply`). When the chunk that
//! owns `reasoning-packets.mjs` / `effect-graph.mjs` lands its own port, the
//! integrator should re-point `writing_proposal` and `verify_proposal` at the
//! canonical implementations and delete the local copies here.
//!
//! `worktree.mjs` has no cross-file dependency: it is ported directly, using a
//! locally defined `ProcessRunner` trait that mirrors the injected
//! `processRunner.run(spec)` contract used throughout the JS remediation
//! modules (see `wf_port::wf015` for the same pattern). This module never
//! shells out itself — every process invocation goes through the caller's
//! `ProcessRunner`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Shared digest helpers.
// ---------------------------------------------------------------------------

/// Recursively sorts object keys, mirroring the `canonical()` helper shared
/// by `reasoning-packets.mjs` and `effect-graph.mjs`.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonical(map.get(key).unwrap()));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Port of the canonicalizing `digestOf(namespace, value)` used by
/// `reasoning-packets.mjs` and `effect-graph.mjs`.
fn digest_of_canonical(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(&canonical(value)).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Port of `verify-proposal.mjs`'s own `digestOf(value)`, which — unlike the
/// canonicalizing helper above — hashes the value's insertion-order
/// `JSON.stringify` output directly, with a fixed `"verification"` namespace.
fn digest_of_verification(value: &Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"verification");
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn get_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

// ---------------------------------------------------------------------------
// Local ports of `reasoning-packets.mjs` pieces (see module doc comment).
// ---------------------------------------------------------------------------

const PROPOSAL_OWNERS: [&str; 4] = ["writing", "designer", "code", "manual"];

fn owner_tier(owner: &str) -> &'static str {
    match owner {
        "writing" => "WRITING",
        "designer" => "DESIGN",
        "code" => "AGENT_GUIDED",
        _ => "MANUAL",
    }
}

fn owner_change_kinds(owner: &str) -> &'static [&'static str] {
    match owner {
        "writing" => &["text"],
        "designer" => &["style", "layout", "asset"],
        "code" => &["source-patch", "config"],
        _ => &[],
    }
}

fn owner_authority_message(owner: &str) -> &'static str {
    match owner {
        "writing" => "writing proposals may change words only",
        "designer" => "designer proposals may not change approved text; layout, style, and assets only",
        "code" => "code proposals may change bounded source only",
        _ => "manual proposals change nothing automatically",
    }
}

/// Local port of `assertOwner` in `reasoning-packets.mjs`.
fn local_assert_owner(owner: &str) -> Result<(), String> {
    if PROPOSAL_OWNERS.contains(&owner) {
        Ok(())
    } else {
        Err(format!("unknown proposal owner: {owner}"))
    }
}

/// Port of `assertOwnerAuthority` in `reasoning-packets.mjs`.
pub fn assert_owner_authority(owner: &str, change: &Value) -> Result<(), String> {
    local_assert_owner(owner)?;
    let kind = get_str(change, "kind").unwrap_or("");
    if owner_change_kinds(owner).contains(&kind) {
        Ok(())
    } else {
        Err(format!(
            "{} (rejected change kind: {})",
            owner_authority_message(owner),
            kind
        ))
    }
}

/// Port of `assertProducerIsNotVerifier` in `reasoning-packets.mjs`.
pub fn assert_producer_is_not_verifier(proposal: &Value, verifier: &Value) -> Result<(), String> {
    let empty = Value::Object(Map::new());
    let producer = proposal.get("producer").unwrap_or(&empty);
    let producer_id = get_str(producer, "id");
    let verifier_id = get_str(verifier, "id");
    if let (Some(p), Some(v)) = (producer_id, verifier_id) {
        if !p.is_empty() && p == v {
            return Err("the producer may not verify its own proposal (identity match)".to_string());
        }
    }
    let producer_ctx = get_str(producer, "contextId");
    let verifier_ctx = get_str(verifier, "contextId");
    if let (Some(p), Some(v)) = (producer_ctx, verifier_ctx) {
        if !p.is_empty() && p == v {
            return Err("the producer may not verify its own proposal (context reuse)".to_string());
        }
    }
    Ok(())
}

/// Local port of the glob matching used by `assertPathAllowed` in
/// `reasoning-packets.mjs` (`matchesGlob`).
fn matches_glob(path: &str, pattern: &str) -> bool {
    if pattern == path {
        return true;
    }
    let mut escaped = String::new();
    for ch in pattern.chars() {
        if ".+^${}()|[]\\".contains(ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    let escaped = escaped.replace("**", "\u{0}").replace('*', "[^/]*").replace('\u{0}', ".*");
    regex::Regex::new(&format!("^{escaped}$"))
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

/// Port of `assertPathAllowed` in `reasoning-packets.mjs`.
pub fn assert_path_allowed(packet: &Value, path: &str) -> Result<(), String> {
    let protected = packet
        .get("protectedSurfaces")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for pattern in &protected {
        if let Some(pattern) = pattern.as_str() {
            if matches_glob(path, pattern) {
                return Err(format!("{path} is a protected surface in this packet"));
            }
        }
    }
    let scope = packet
        .get("scope")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let allowed = scope.iter().any(|pattern| {
        pattern
            .as_str()
            .map(|pattern| pattern == path || matches_glob(path, pattern))
            .unwrap_or(false)
    });
    if allowed {
        Ok(())
    } else {
        Err(format!("{path} is outside the packet scope"))
    }
}

/// Local port of the shared SNIP-16 `reasoningProposal({ packet, owner,
/// changes, binding, extra })` in `reasoning-packets.mjs`, used by both
/// `writing_proposal` here and (eventually) `design_proposal`/`code_proposal`
/// once their owning chunks land.
fn local_reasoning_proposal(
    packet: &Value,
    owner: &str,
    changes: &[Value],
    binding: &Value,
    extra: Map<String, Value>,
) -> Result<Value, String> {
    local_assert_owner(owner)?;
    let packet_owner = get_str(packet, "owner").unwrap_or("");
    if packet_owner != owner {
        return Err(format!("packet owner {packet_owner} cannot produce a {owner} proposal"));
    }
    if changes.is_empty() {
        return Err("a proposal requires at least one change".to_string());
    }
    for change in changes {
        assert_owner_authority(owner, change)?;
        let path = get_str(change, "path").unwrap_or("");
        assert_path_allowed(packet, path)?;
    }
    let mut target_paths: Vec<String> = changes
        .iter()
        .filter_map(|change| get_str(change, "path").map(str::to_string))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    target_paths.sort();

    let finding_ids = packet
        .get("findingIds")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let scope: Vec<String> = packet
        .get("scope")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let producer = packet.get("producer").cloned().unwrap_or_else(|| json!({}));
    let packet_digest = packet.get("digest").cloned().unwrap_or(Value::Null);

    let mut body = Map::new();
    body.insert("schemaVersion".to_string(), json!(1));
    body.insert("kind".to_string(), json!("legion-remediation-proposal"));
    body.insert("findingIds".to_string(), finding_ids);
    body.insert("owner".to_string(), json!(owner));
    body.insert("producer".to_string(), producer);
    body.insert("packetDigest".to_string(), packet_digest);
    body.insert("targetPaths".to_string(), json!(target_paths));
    body.insert(
        "preconditions".to_string(),
        json!([format!("changes stay within packet scope {}", scope.join(", "))]),
    );
    body.insert("changes".to_string(), Value::Array(changes.to_vec()));
    body.insert("patch".to_string(), Value::Null);
    body.insert("expectedBehavior".to_string(), json!([]));
    body.insert("publicSurfaceChanges".to_string(), json!([]));
    body.insert("affectedFamilies".to_string(), json!([]));
    body.insert("validationPlan".to_string(), json!([]));
    body.insert(
        "rollback".to_string(),
        json!({ "strategy": "restore-checkpoint", "checkpointRequired": true }),
    );
    body.insert("tier".to_string(), json!(owner_tier(owner)));
    body.insert("binding".to_string(), binding.clone());
    for (key, value) in extra {
        body.insert(key, value);
    }
    let id = digest_of_canonical("remediation-proposal", &Value::Object(body.clone()));
    body.insert("id".to_string(), json!(id));
    Ok(Value::Object(body))
}

/// Local port of `blocksAutoApply` in `effect-graph.mjs`.
fn local_blocks_auto_apply(effect_graph: &Value) -> bool {
    if let Some(unplanned) = effect_graph.get("unplannedPublicSurfaceChanges").and_then(Value::as_array) {
        return !unplanned.is_empty();
    }
    effect_graph
        .get("publicSurfaceChanges")
        .and_then(Value::as_array)
        .map(|values| !values.is_empty())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// writing-proposal.mjs
// ---------------------------------------------------------------------------

/// Port of `writingProposal` in `writing-proposal.mjs`. Words only — a
/// non-text change or a change missing `contentItemId` is rejected outright
/// rather than trimmed.
pub fn writing_proposal(packet: &Value, changes: &[Value], binding: &Value) -> Result<Value, String> {
    for change in changes {
        // Authority first: a non-text change is rejected as an authority
        // breach, not as a missing-field problem.
        assert_owner_authority("writing", change)?;
        if get_str(change, "contentItemId").map(|s| s.is_empty()).unwrap_or(true) {
            return Err("every writing change must name the content item it rewrites".to_string());
        }
    }

    let content_item_ids: Vec<String> = {
        let mut ids: Vec<String> = changes
            .iter()
            .filter_map(|change| get_str(change, "contentItemId").map(str::to_string))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        ids.sort();
        ids
    };

    let mut extra = Map::new();
    extra.insert(
        "expectedBehavior".to_string(),
        json!(["the named content items read as proposed and remain claim-supported"]),
    );
    extra.insert("affectedFamilies".to_string(), json!(["copy", "narrative"]));
    extra.insert(
        "validationPlan".to_string(),
        json!(["affected-provider-rerun:copy", "affected-provider-rerun:narrative", "claim-proof-recheck"]),
    );
    extra.insert("contentItemIds".to_string(), json!(content_item_ids));

    local_reasoning_proposal(packet, "writing", changes, binding, extra)
}

// ---------------------------------------------------------------------------
// verify-proposal.mjs
// ---------------------------------------------------------------------------

pub const VERIFICATION_SCHEMA_VERSION: u32 = 1;

fn has_effects(effect_graph: &Value) -> bool {
    for key in ["changedFiles", "changedSymbols", "changedConfig", "contentItems"] {
        if effect_graph
            .get(key)
            .and_then(Value::as_array)
            .map(|values| !values.is_empty())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Port of `verifyProposal` in `verify-proposal.mjs`. Adversarial by
/// construction: the verifier identity must differ from the producer, every
/// producer-supplied pass claim is discarded, and a verification with no
/// providers and no gates while the effect graph shows real effects is
/// rejected as vacuous rather than accepted as clean.
pub fn verify_proposal(
    proposal: &Value,
    effect_graph: &Value,
    verifier: &Value,
    provider_results: &[Value],
    gate_results: &[Value],
    binding: &Value,
) -> Result<Value, String> {
    if get_str(verifier, "id").map(|s| s.is_empty()).unwrap_or(true) {
        return Err("verification requires a verifier identity".to_string());
    }
    assert_producer_is_not_verifier(proposal, verifier)?;

    let mut coverage_gaps: Vec<Value> = Vec::new();

    let result_by_provider: std::collections::HashMap<&str, &Value> = provider_results
        .iter()
        .filter_map(|result| get_str(result, "provider").map(|id| (id, result)))
        .collect();
    let gate_by_id: std::collections::HashMap<&str, &Value> = gate_results
        .iter()
        .filter_map(|gate| get_str(gate, "id").map(|id| (id, gate)))
        .collect();

    let required_providers: Vec<String> = effect_graph
        .get("requiredProviders")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    for provider_id in &required_providers {
        match result_by_provider.get(provider_id.as_str()) {
            None => {
                coverage_gaps.push(json!({ "kind": "missing-affected-provider", "provider": provider_id }));
            }
            Some(result) => {
                let complete = result.get("complete").and_then(Value::as_bool).unwrap_or(false);
                if !complete {
                    coverage_gaps.push(json!({
                        "kind": "affected-provider-incomplete",
                        "provider": provider_id,
                        "status": result.get("status").cloned().unwrap_or(Value::Null),
                    }));
                    continue;
                }
                let status = get_str(result, "status").unwrap_or("");
                if status != "pass" {
                    coverage_gaps.push(json!({
                        "kind": "affected-provider-failed",
                        "provider": provider_id,
                        "status": result.get("status").cloned().unwrap_or(Value::Null),
                    }));
                }
            }
        }
    }

    let required_gates: Vec<String> = effect_graph
        .get("requiredGates")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    for gate_id in &required_gates {
        match gate_by_id.get(gate_id.as_str()) {
            None => {
                coverage_gaps.push(json!({ "kind": "missing-baseline-gate", "gate": gate_id }));
            }
            Some(gate) => {
                let passed = gate.get("passed").and_then(Value::as_bool).unwrap_or(false);
                if !passed {
                    coverage_gaps.push(json!({ "kind": "baseline-gate-failed", "gate": gate_id }));
                }
            }
        }
    }

    if has_effects(effect_graph) && provider_results.is_empty() && gate_results.is_empty() {
        coverage_gaps.push(json!({
            "kind": "vacuous-verification",
            "reason": "effects exist but no provider or gate evidence was supplied",
        }));
    }

    if local_blocks_auto_apply(effect_graph) {
        let surfaces = effect_graph
            .get("unplannedPublicSurfaceChanges")
            .cloned()
            .unwrap_or_else(|| json!([]));
        coverage_gaps.push(json!({ "kind": "unplanned-public-surface-change", "surfaces": surfaces }));
    }

    coverage_gaps.sort_by(|a, b| {
        serde_json::to_string(a)
            .unwrap_or_default()
            .cmp(&serde_json::to_string(b).unwrap_or_default())
    });

    let valid = coverage_gaps.is_empty();

    let mut body = Map::new();
    body.insert("schemaVersion".to_string(), json!(VERIFICATION_SCHEMA_VERSION));
    body.insert("kind".to_string(), json!("legion-remediation-verification"));
    body.insert("proposalId".to_string(), proposal.get("id").cloned().unwrap_or(Value::Null));
    body.insert(
        "patchDigest".to_string(),
        proposal
            .get("patch")
            .and_then(|patch| patch.get("digest"))
            .cloned()
            .unwrap_or(Value::Null),
    );
    body.insert(
        "effectGraphDigest".to_string(),
        effect_graph.get("digest").cloned().unwrap_or(Value::Null),
    );
    body.insert("verifiedBy".to_string(), json!("neutral-verification"));
    body.insert(
        "verifier".to_string(),
        json!({
            "id": get_str(verifier, "id"),
            "contextId": verifier.get("contextId").cloned().unwrap_or(Value::Null),
        }),
    );
    body.insert(
        "producer".to_string(),
        json!({
            "id": proposal.get("producer").and_then(|p| p.get("id")).cloned().unwrap_or(Value::Null),
            "contextId": proposal.get("producer").and_then(|p| p.get("contextId")).cloned().unwrap_or(Value::Null),
        }),
    );
    body.insert("trustedProducerAssertions".to_string(), json!(false));
    body.insert("providersChecked".to_string(), json!(required_providers.len()));
    body.insert("gatesChecked".to_string(), json!(required_gates.len()));
    body.insert("coverageGaps".to_string(), Value::Array(coverage_gaps));
    body.insert("valid".to_string(), json!(valid));
    body.insert("binding".to_string(), binding.clone());

    let digest = digest_of_verification(&Value::Object(body.clone()));
    body.insert("digest".to_string(), json!(digest));
    Ok(Value::Object(body))
}

/// Port of `buildVerificationSchema` in `verify-proposal.mjs`.
pub fn build_verification_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/remediation/verification-v1.json",
        "title": "RemediationVerificationV1",
        "type": "object",
        "required": [
            "schemaVersion", "kind", "proposalId", "patchDigest", "effectGraphDigest", "verifiedBy", "verifier",
            "producer", "trustedProducerAssertions", "providersChecked", "gatesChecked",
            "coverageGaps", "valid", "binding", "digest",
        ],
        "properties": {
            "schemaVersion": { "const": VERIFICATION_SCHEMA_VERSION },
            "kind": { "const": "legion-remediation-verification" },
            "proposalId": { "type": "string" },
            "patchDigest": { "type": ["string", "null"] },
            "effectGraphDigest": { "type": ["string", "null"] },
            "verifiedBy": { "const": "neutral-verification" },
            "verifier": {
                "type": "object",
                "required": ["id", "contextId"],
                "properties": { "id": { "type": "string", "minLength": 1 }, "contextId": { "type": ["string", "null"] } },
                "additionalProperties": false,
            },
            "producer": {
                "type": "object",
                "required": ["id", "contextId"],
                "properties": { "id": { "type": ["string", "null"] }, "contextId": { "type": ["string", "null"] } },
                "additionalProperties": false,
            },
            "trustedProducerAssertions": { "const": false },
            "providersChecked": { "type": "integer", "minimum": 0 },
            "gatesChecked": { "type": "integer", "minimum": 0 },
            "coverageGaps": { "type": "array", "items": { "type": "object" } },
            "valid": { "type": "boolean" },
            "binding": { "type": "object" },
            "digest": { "type": "string", "pattern": "^sha256:" },
        },
        "additionalProperties": false,
    })
}

// ---------------------------------------------------------------------------
// worktree.mjs
// ---------------------------------------------------------------------------

/// Port of the ad hoc `{ exitCode, stderr }` shape the JS `processRunner`
/// resolves to (mirrors `wf_port::wf015::ProcessOutcome`; kept local to this
/// module since `wf015` is a sibling, independently owned chunk).
#[derive(Debug, Clone, Default)]
pub struct ProcessOutcome {
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

/// Port of the injected `processRunner.run(spec)` contract used throughout
/// the JS remediation modules.
pub trait ProcessRunner {
    fn run<'a>(&'a self, spec: ProcessSpec) -> Pin<Box<dyn Future<Output = ProcessOutcome> + Send + 'a>>;
}

#[derive(Debug, Clone)]
pub struct RemediationWorktree {
    pub path: PathBuf,
    pub base_commit: String,
    pub cleanup: Vec<String>,
}

/// Port of `createRemediationWorktree` in `worktree.mjs`. Isolated
/// remediation worktree per SNIP-WORKTREE-01 — never uses the caller's
/// primary worktree as the remediation target.
pub async fn create_remediation_worktree(
    repo_root: &Path,
    repo_git_common_dir: &Path,
    base_commit: &str,
    run_id: &str,
    process_runner: &dyn ProcessRunner,
) -> Result<RemediationWorktree, String> {
    let path = repo_git_common_dir.join("legion-worktrees").join(run_id);
    let result = process_runner
        .run(ProcessSpec {
            executable: "git".to_string(),
            args: vec![
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                path.to_string_lossy().into_owned(),
                base_commit.to_string(),
            ],
            cwd: repo_root.to_path_buf(),
        })
        .await;
    if result.exit_code != Some(0) {
        let reason = result
            .stderr
            .or(result.error)
            .unwrap_or_else(|| "unknown".to_string());
        return Err(format!("git worktree add failed: {reason}"));
    }
    Ok(RemediationWorktree {
        cleanup: vec![
            "git".to_string(),
            "worktree".to_string(),
            "remove".to_string(),
            "--force".to_string(),
            path.to_string_lossy().into_owned(),
        ],
        path,
        base_commit: base_commit.to_string(),
    })
}

#[derive(Debug, Clone)]
pub struct RemoveWorktreeResult {
    pub removed: bool,
    pub error: Option<String>,
}

/// Port of `removeRemediationWorktree` in `worktree.mjs`. Never runs from
/// inside the worktree being removed — Windows refuses to delete a directory
/// that is the process cwd, and the parent of the worktree is always outside
/// it and exists after removal.
pub async fn remove_remediation_worktree(
    path: &Path,
    process_runner: &dyn ProcessRunner,
) -> RemoveWorktreeResult {
    let cwd = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let result = process_runner
        .run(ProcessSpec {
            executable: "git".to_string(),
            args: vec![
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                path.to_string_lossy().into_owned(),
            ],
            cwd,
        })
        .await;
    let removed = result.exit_code == Some(0);
    RemoveWorktreeResult {
        removed,
        error: if removed {
            None
        } else {
            Some(result.stderr.unwrap_or_else(|| "unknown".to_string()))
        },
    }
}

/// Port of `worktreeReceipt` in `worktree.mjs`.
pub fn worktree_receipt(path: &Path, base_commit: &str, run_id: &str, cleanup: &[String]) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-worktree",
        "path": path.to_string_lossy(),
        "baseCommit": base_commit,
        "runId": run_id,
        "cleanup": cleanup.to_vec(),
        "primaryWorktreeUntouched": true,
    })
}
