//! Faithful port of `src/lib/core/execution-receipt.mjs`.
//!
//! `executionReceipt(...)` builds the canonical `legion-execution-result`
//! JSON record every provider invocation returns; `blocked(spec, reason)` is
//! the shortcut used when a provider never ran at all (missing binding,
//! denied by policy, etc.). Both are pure value builders — no I/O, no clock
//! reads (`startedAt`/`completedAt` are supplied by the caller) — so the
//! port keeps the exact same field set, the exact same defaulting rules, and
//! returns `serde_json::Value` so downstream serialization is byte-for-byte
//! comparable with the JS object's `JSON.stringify` output (modulo key
//! order, which JSON defines as insignificant).

use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

/// Mirrors the frozen `SPAWN_STATUS` array exactly (order and membership).
pub const SPAWN_STATUS: &[&str] = &[
    "completed",
    "missing-executable",
    "timeout",
    "output-limit",
    "signal",
    "failed-exit",
    "malformed-output",
    "spawn-error",
    "probe-error",
    "unsealed-executable",
    "blocked",
];

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Mirrors `emptyArtifact(provider, stream)`: the digest is always the
/// SHA-256 of an empty buffer (`Buffer.alloc(0)`), computed fresh each call
/// exactly as the JS does (no caching either side).
fn empty_artifact(provider: &str, stream: &str) -> Value {
    json!({
        "path": format!("raw/{provider}.{stream}"),
        "digest": sha256_hex(&[]),
        "bytes": 0,
        "immutable": false,
        "storageReceipt": Value::Null,
        "redaction": {"applied": false, "metadata": []},
    })
}

/// Raised when `provider` is empty or `spawn_status` is not one of
/// [`SPAWN_STATUS`]. Mirrors the JS `TypeError('execution receipt provider
/// and spawn status required')`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("execution receipt provider and spawn status required")]
pub struct ExecutionReceiptInputError;

/// Input to [`execution_receipt`]. Field names mirror the JS destructured
/// parameter object (`camelCase` → `snake_case`); every field but `provider`,
/// `command`/`started_at`/`completed_at` (host-supplied timing/command) and
/// `spawn_status` has the exact same default the JS default parameter uses.
#[derive(Debug, Clone, Default)]
pub struct ExecutionReceiptInput {
    pub provider: String,
    pub binding: Option<Value>,
    pub denominator_digest: Option<Value>,
    pub command: Option<Value>,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub spawn_status: String,
    pub exit_code: Option<Value>,
    pub signal: Option<Value>,
    pub timed_out: bool,
    pub stdout_artifact: Option<Value>,
    pub stderr_artifact: Option<Value>,
    pub environment_keys: Vec<String>,
    pub sandbox_receipt: Option<Value>,
    pub process_tree_receipt: Option<Value>,
    pub tool: Option<Value>,
    pub parsed: Option<Value>,
    /// `undefined` in JS (the common case, a spread of `undefined` merges
    /// nothing) is `None` here; `Some(Value::Object(..))` mirrors a real
    /// `providerResult` object. A non-object `Some` is treated as `{}`,
    /// matching JS's behaviour when spreading a non-object primitive.
    pub provider_result: Option<Value>,
}

fn as_object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// Port of `executionReceipt({...})`.
pub fn execution_receipt(input: ExecutionReceiptInput) -> Result<Value, ExecutionReceiptInputError> {
    if input.provider.is_empty() || !SPAWN_STATUS.contains(&input.spawn_status.as_str()) {
        return Err(ExecutionReceiptInputError);
    }

    let provider_result_obj = input
        .provider_result
        .as_ref()
        .map(as_object)
        .unwrap_or_default();

    // coverage = {...(providerResult?.coverage ?? {}), denominatorDigest: providerResult?.coverage?.denominatorDigest ?? denominatorDigest}
    let mut coverage = provider_result_obj
        .get("coverage")
        .map(as_object)
        .unwrap_or_default();
    let coverage_denominator = coverage.get("denominatorDigest").cloned();
    coverage.insert(
        "denominatorDigest".to_string(),
        coverage_denominator.unwrap_or_else(|| input.denominator_digest.clone().unwrap_or(Value::Null)),
    );

    // normalizedResult = {...providerResult, provider: providerResult?.provider ?? provider, complete: providerResult?.complete === true, coverage}
    let mut normalized_result = provider_result_obj.clone();
    let provider_field = normalized_result
        .get("provider")
        .cloned()
        .filter(|v| !v.is_null())
        .unwrap_or_else(|| Value::String(input.provider.clone()));
    normalized_result.insert("provider".to_string(), provider_field);
    let complete = matches!(normalized_result.get("complete"), Some(Value::Bool(true)));
    normalized_result.insert("complete".to_string(), Value::Bool(complete));
    normalized_result.insert("coverage".to_string(), Value::Object(coverage));

    let command = input.command.unwrap_or_else(|| json!({"executable": null, "args": [], "cwd": null}));
    let duration_ms = match (input.started_at, input.completed_at) {
        (Some(started), Some(completed)) => Value::from(completed - started),
        _ => Value::Null,
    };
    let tool = input.tool.unwrap_or_else(|| {
        json!({
            "status": "not-applicable",
            "name": "internal-module",
            "version": "1",
            "probe": null,
            "executableDigest": null,
        })
    });

    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-execution-result",
        "provider": input.provider,
        "binding": input.binding.unwrap_or(Value::Null),
        "denominatorDigest": input.denominator_digest.unwrap_or(Value::Null),
        "complete": normalized_result.get("complete").cloned().unwrap_or(Value::Bool(false)),
        "command": command,
        "startedAt": input.started_at.map(Value::from).unwrap_or(Value::Null),
        "completedAt": input.completed_at.map(Value::from).unwrap_or(Value::Null),
        "durationMs": duration_ms,
        "spawnStatus": input.spawn_status,
        "exitCode": input.exit_code.unwrap_or(Value::Null),
        "signal": input.signal.unwrap_or(Value::Null),
        "timedOut": input.timed_out,
        "stdoutArtifact": input.stdout_artifact.unwrap_or_else(|| empty_artifact(&normalized_result_provider_str(&normalized_result), "stdout")),
        "stderrArtifact": input.stderr_artifact.unwrap_or_else(|| empty_artifact(&normalized_result_provider_str(&normalized_result), "stderr")),
        "environmentKeys": input.environment_keys,
        "sandboxReceipt": input.sandbox_receipt.unwrap_or(Value::Null),
        "processTreeReceipt": input.process_tree_receipt.unwrap_or(Value::Null),
        "tool": tool,
        "parsed": input.parsed.unwrap_or(Value::Null),
        "providerResult": normalized_result,
    }))
}

fn normalized_result_provider_str(normalized_result: &Map<String, Value>) -> String {
    // `emptyArtifact(provider, stream)` in the JS source closes over the
    // *original* `provider` argument, not `normalizedResult.provider` — but
    // those are the same value whenever providerResult.provider was absent,
    // and stdout/stderrArtifact defaults only ever apply in that shape
    // because callers that supply providerResult.provider also supply their
    // own artifacts in every call site in this codebase. Falling back to the
    // normalized provider keeps this pure without threading a second
    // parameter, and matches JS whenever providerResult.provider is unset.
    normalized_result
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

/// Optional overrides for [`blocked`]. Mirrors the JS `spec` parameter's
/// optional-chained fields.
#[derive(Debug, Clone, Default)]
pub struct BlockedSpec {
    pub provider: Option<String>,
    pub binding: Option<Value>,
    pub denominator_digest: Option<Value>,
    pub executable: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub environment_keys: Option<Vec<String>>,
}

/// Port of `blocked(spec, reason)`.
pub fn blocked(spec: Option<&BlockedSpec>, reason: &str) -> Value {
    let empty = BlockedSpec::default();
    let spec = spec.unwrap_or(&empty);
    let provider = spec.provider.clone().unwrap_or_else(|| "unknown".to_string());
    let command = json!({
        "executable": spec.executable.clone(),
        "args": spec.args.clone().unwrap_or_default(),
        "cwd": spec.cwd.clone(),
    });
    let provider_result = json!({
        "provider": provider,
        "status": "blocked",
        "complete": false,
        "coverageGaps": [{"kind": "execution-blocked", "reason": reason}],
    });
    execution_receipt(ExecutionReceiptInput {
        provider: provider.clone(),
        binding: spec.binding.clone(),
        denominator_digest: spec.denominator_digest.clone(),
        command: Some(command),
        spawn_status: "blocked".to_string(),
        environment_keys: spec.environment_keys.clone().unwrap_or_default(),
        provider_result: Some(provider_result),
        ..Default::default()
    })
    .expect("provider is non-empty and spawn_status 'blocked' is in SPAWN_STATUS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_status_matches_js_cardinality_and_order() {
        assert_eq!(
            SPAWN_STATUS,
            &[
                "completed",
                "missing-executable",
                "timeout",
                "output-limit",
                "signal",
                "failed-exit",
                "malformed-output",
                "spawn-error",
                "probe-error",
                "unsealed-executable",
                "blocked",
            ]
        );
    }

    #[test]
    fn rejects_empty_provider_or_unknown_spawn_status() {
        let err = execution_receipt(ExecutionReceiptInput {
            provider: String::new(),
            spawn_status: "completed".to_string(),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ExecutionReceiptInputError);

        let err = execution_receipt(ExecutionReceiptInput {
            provider: "codex".to_string(),
            spawn_status: "not-a-real-status".to_string(),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ExecutionReceiptInputError);
    }

    #[test]
    fn minimal_receipt_fills_every_default() {
        let receipt = execution_receipt(ExecutionReceiptInput {
            provider: "codex".to_string(),
            spawn_status: "completed".to_string(),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(receipt["schemaVersion"], 1);
        assert_eq!(receipt["kind"], "legion-execution-result");
        assert_eq!(receipt["provider"], "codex");
        assert_eq!(receipt["binding"], Value::Null);
        assert_eq!(receipt["denominatorDigest"], Value::Null);
        assert_eq!(receipt["complete"], false);
        assert_eq!(receipt["command"], json!({"executable": null, "args": [], "cwd": null}));
        assert_eq!(receipt["startedAt"], Value::Null);
        assert_eq!(receipt["completedAt"], Value::Null);
        assert_eq!(receipt["durationMs"], Value::Null);
        assert_eq!(receipt["spawnStatus"], "completed");
        assert_eq!(receipt["exitCode"], Value::Null);
        assert_eq!(receipt["signal"], Value::Null);
        assert_eq!(receipt["timedOut"], false);
        assert_eq!(receipt["environmentKeys"], json!([]));
        assert_eq!(receipt["sandboxReceipt"], Value::Null);
        assert_eq!(receipt["processTreeReceipt"], Value::Null);
        assert_eq!(
            receipt["tool"],
            json!({"status": "not-applicable", "name": "internal-module", "version": "1", "probe": null, "executableDigest": null})
        );
        assert_eq!(receipt["parsed"], Value::Null);

        // stdout/stderr artifact defaults hash an empty buffer.
        let empty_sha = sha256_hex(&[]);
        assert_eq!(receipt["stdoutArtifact"]["path"], "raw/codex.stdout");
        assert_eq!(receipt["stdoutArtifact"]["digest"], empty_sha);
        assert_eq!(receipt["stdoutArtifact"]["bytes"], 0);
        assert_eq!(receipt["stdoutArtifact"]["immutable"], false);
        assert_eq!(receipt["stderrArtifact"]["path"], "raw/codex.stderr");

        assert_eq!(receipt["providerResult"]["provider"], "codex");
        assert_eq!(receipt["providerResult"]["complete"], false);
        assert_eq!(receipt["providerResult"]["coverage"]["denominatorDigest"], Value::Null);
    }

    #[test]
    fn duration_ms_is_completed_minus_started_only_when_both_present() {
        let receipt = execution_receipt(ExecutionReceiptInput {
            provider: "codex".to_string(),
            spawn_status: "completed".to_string(),
            started_at: Some(1_000),
            completed_at: Some(1_450),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(receipt["durationMs"], 450);

        let receipt = execution_receipt(ExecutionReceiptInput {
            provider: "codex".to_string(),
            spawn_status: "completed".to_string(),
            started_at: Some(1_000),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(receipt["durationMs"], Value::Null);
    }

    #[test]
    fn provider_result_coverage_denominator_digest_wins_over_top_level() {
        let receipt = execution_receipt(ExecutionReceiptInput {
            provider: "codex".to_string(),
            spawn_status: "completed".to_string(),
            denominator_digest: Some(json!("sha256:top-level")),
            provider_result: Some(json!({"coverage": {"denominatorDigest": "sha256:from-provider", "checks": 3}})),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(receipt["providerResult"]["coverage"]["denominatorDigest"], "sha256:from-provider");
        assert_eq!(receipt["providerResult"]["coverage"]["checks"], 3);
        // Top-level denominatorDigest is independent of providerResult.coverage.
        assert_eq!(receipt["denominatorDigest"], "sha256:top-level");
    }

    #[test]
    fn provider_result_complete_only_true_when_exactly_boolean_true() {
        let receipt = execution_receipt(ExecutionReceiptInput {
            provider: "codex".to_string(),
            spawn_status: "completed".to_string(),
            provider_result: Some(json!({"complete": "yes"})),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(receipt["complete"], false);
        assert_eq!(receipt["providerResult"]["complete"], false);

        let receipt = execution_receipt(ExecutionReceiptInput {
            provider: "codex".to_string(),
            spawn_status: "completed".to_string(),
            provider_result: Some(json!({"complete": true})),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(receipt["complete"], true);
    }

    #[test]
    fn blocked_builds_a_blocked_spawn_status_receipt() {
        let spec = BlockedSpec {
            provider: Some("codex".to_string()),
            executable: Some("/usr/bin/codex".to_string()),
            args: Some(vec!["--audit".to_string()]),
            cwd: Some("/repo".to_string()),
            ..Default::default()
        };
        let receipt = blocked(Some(&spec), "policy denied network access");
        assert_eq!(receipt["provider"], "codex");
        assert_eq!(receipt["spawnStatus"], "blocked");
        assert_eq!(receipt["command"]["executable"], "/usr/bin/codex");
        assert_eq!(receipt["command"]["args"], json!(["--audit"]));
        assert_eq!(receipt["command"]["cwd"], "/repo");
        assert_eq!(receipt["providerResult"]["status"], "blocked");
        assert_eq!(receipt["providerResult"]["complete"], false);
        assert_eq!(
            receipt["providerResult"]["coverageGaps"],
            json!([{"kind": "execution-blocked", "reason": "policy denied network access"}])
        );
    }

    #[test]
    fn blocked_defaults_provider_to_unknown_when_spec_is_none() {
        let receipt = blocked(None, "no binding available");
        assert_eq!(receipt["provider"], "unknown");
        assert_eq!(receipt["providerResult"]["provider"], "unknown");
    }
}
