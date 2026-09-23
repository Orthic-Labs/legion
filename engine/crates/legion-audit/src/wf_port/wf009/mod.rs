//! wf009 — `src/lib/providers` executor surface.
//!
//! Most of this area (`executor/external-process.mjs`,
//! `executor/output-limit.mjs`, `evidence-authority.mjs`, and the
//! `executor/index.mjs` `runtime-script`/`legacy-check`/`reasoning-contract`/
//! `external-process` runner dispatch) already has native Rust coverage:
//!
//! - `evidence-authority.mjs`'s `validateEvidenceRefs` is faithfully ported
//!   at [`crate::native_providers::architecture::evidence::validate_refs`]
//!   (see that module's doc comment: "Port of `validateEvidenceRefs` from
//!   `evidence-authority.mjs`").
//! - `executor/external-process.mjs`'s `runExternal`/`blocked`/
//!   `pickEnvironment` are superseded by the newer, stricter
//!   `legion_effects::executor::EffectExecutor` + `ExecutionReceipt`
//!   pipeline (process spawn, executable sealing/qualification, timeout,
//!   output capping, environment allowlisting, sandbox receipts all present
//!   there), which is validated as the production entry point in
//!   `crate::execution::validate_external_receipt`. The JS test file
//!   `tests/provider-executor.test.mjs` exercises exactly this behaviour
//!   (allowlist blocking, shell-forbidden, environment sanitizing, timeout,
//!   output cap) and every assertion has a native analogue.
//! - `executor/output-limit.mjs`'s `createOutputCollector` truncate-on-limit
//!   behaviour is reimplemented directly inside `legion_effects::unix`
//!   (`stdout_limit`/`stderr_limit`, `StopReason::OutputLimited`).
//! - `executor/index.mjs`'s runner-kind dispatch (`runtime-script`,
//!   `legacy-check`, `reasoning-contract`, `external-process`) is ported at
//!   `crate::plan` (the `match runner_kind` block building `ProviderKind`).
//!
//! Two pieces of this chunk did **not** have a native counterpart and are
//! ported here:
//!
//! 1. `executor/imported-artifact.mjs`'s `importedArtifactReceipt` — the
//!    flat "pass" receipt shape built once an imported artifact's binding is
//!    verified. `ingestImportedArtifact`/`assertArtifactBinding` itself is
//!    already ported as [`legion_runtime::p5_core::adapters_chain_adjudication::assert_artifact_binding`],
//!    but nothing built the receipt object on top of it.
//! 2. `executor/external-process.mjs`'s `normalizeExecutorAction` — the
//!    `{operation, effectClass, target, arguments}` executor-action
//!    validator used by `runExternal`'s `parseAction` path. A
//!    same-named-but-unrelated `normalize_executor_action` exists in
//!    `legion_runtime::scheduler` (different field set: `actionId`,
//!    `operation`, `effect`, `payloadDigest` — a scheduler work-unit
//!    envelope, not this executor-action schema), so it does not cover this
//!    function.
//!
//! **Known gap for the integrator:** `crate::plan`'s runner-kind dispatch
//! does not have an `"imported-artifact"` arm (it falls through to the
//! `_ => unsupported runner kind` error), while JS's `executeRunner`
//! dispatches `imported-artifact` to `importedArtifactReceipt`. `plan.rs` is
//! outside this chunk's owned paths; the integrator should add an
//! `"imported-artifact" => ProviderKind::...` arm (plus wiring to call
//! [`imported_artifact_receipt`] below) if/when that runner kind is wired
//! into a frozen plan.

use serde_json::{Map, Value};

/// Error mirroring JS `TypeError`/`IntegrityError` throws from
/// `imported-artifact.mjs` and the `LEGION_ACTION_MALFORMED` throws from
/// `external-process.mjs`'s `normalizeExecutorAction`.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ExecutorPortError {
    /// Port of `IntegrityError('${label} binding does not match sealed plan')`
    /// as raised by `assertArtifactBinding` inside `ingestImportedArtifact`.
    #[error("{0} binding does not match sealed plan")]
    BindingMismatch(String),
    /// Port of `TypeError('imported artifact requires path and digest')`.
    #[error("imported artifact requires path and digest")]
    MissingPathOrDigest,
    /// Port of the `LEGION_ACTION_MALFORMED` throws in `normalizeExecutorAction`.
    #[error("{message}")]
    ActionMalformed {
        message: String,
        /// JSON Pointer-ish path into the offending value, mirrors JS `guidance.path`.
        path: String,
    },
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::String(text) => Value::String(text.replace('\\', "/")),
        other => other.clone(),
    }
}

fn binding_digest(value: &Value) -> String {
    // Port of `digest()` in `src/lib/core/binding.mjs`: sha256 over the
    // canonical JSON-serialized value.
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)))
}

fn same_binding(left: Option<&Value>, right: Option<&Value>) -> bool {
    let left = left.cloned().unwrap_or(Value::Null);
    let right = right.cloned().unwrap_or(Value::Null);
    binding_digest(&left) == binding_digest(&right)
}

/// Port of `ingestImportedArtifact` / `assertArtifactBinding(artifact,
/// binding, 'imported artifact')` from `imported-artifact.mjs`. Returns the
/// artifact unchanged (as JS does) once its `binding` field matches the
/// expected binding by canonical digest.
pub fn ingest_imported_artifact(
    artifact: &Value,
    binding: &Value,
) -> Result<Value, ExecutorPortError> {
    let artifact_binding = artifact.get("binding");
    if artifact.is_null() || !same_binding(artifact_binding, Some(binding)) {
        return Err(ExecutorPortError::BindingMismatch("imported artifact".into()));
    }
    Ok(artifact.clone())
}

/// Port of `importedArtifactReceipt(provider, artifact, binding)` from
/// `executor/imported-artifact.mjs`.
pub fn imported_artifact_receipt(
    provider: &str,
    artifact: &Value,
    binding: &Value,
) -> Result<Value, ExecutorPortError> {
    let verified = ingest_imported_artifact(artifact, binding)?;
    let digest = verified.get("digest").and_then(Value::as_str);
    let path = verified.get("path").and_then(Value::as_str);
    let (Some(digest), Some(path)) = (digest, path) else {
        return Err(ExecutorPortError::MissingPathOrDigest);
    };
    let bytes = verified.get("bytes").cloned().unwrap_or(Value::Null);
    let media_type = verified.get("mediaType").cloned().unwrap_or(Value::Null);
    Ok(serde_json::json!({
        "schemaVersion": 1,
        "kind": "legion-imported-artifact-receipt",
        "provider": provider,
        "status": "pass",
        "complete": true,
        "binding": binding,
        "artifact": {
            "path": path,
            "digest": digest,
            "bytes": bytes,
            "mediaType": media_type,
        }
    }))
}

/// The exact field set `normalizeExecutorAction` accepts, mirroring JS
/// `ACTION_FIELDS`.
const ACTION_FIELDS: [&str; 4] = ["operation", "effectClass", "target", "arguments"];

/// A normalized executor action, mirroring the frozen object
/// `normalizeExecutorAction` returns: `{operation, effectClass, target,
/// arguments}` with `operation`/`effectClass`/`target` trimmed strings
/// (`effectClass` upper-cased) and `arguments` a plain object (defaulting to
/// `{}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorAction {
    pub operation: String,
    pub effect_class: String,
    pub target: String,
    pub arguments: Map<String, Value>,
}

fn malformed(message: impl Into<String>, path: impl Into<String>) -> ExecutorPortError {
    ExecutorPortError::ActionMalformed {
        message: message.into(),
        path: path.into(),
    }
}

/// Port of `normalizeExecutorAction` from `executor/external-process.mjs`.
/// Validates and normalizes a parsed external-process action payload
/// (`spec.parseAction`); throws `LEGION_ACTION_MALFORMED` in JS for a
/// non-object value, an unknown field, or a missing/empty required string
/// field.
pub fn normalize_executor_action(value: &Value) -> Result<ExecutorAction, ExecutorPortError> {
    let Some(object) = value.as_object() else {
        return Err(malformed("executor action must be an object", "$"));
    };
    for key in object.keys() {
        if !ACTION_FIELDS.contains(&key.as_str()) {
            return Err(malformed(
                format!("unknown executor action field: {key}"),
                format!("$.{key}"),
            ));
        }
    }
    for field in ["operation", "effectClass", "target"] {
        let ok = object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
        if !ok {
            return Err(malformed(
                format!("executor action {field} is required"),
                format!("$.{field}"),
            ));
        }
    }
    let arguments = match object.get("arguments") {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    Ok(ExecutorAction {
        operation: object["operation"].as_str().unwrap().trim().to_owned(),
        effect_class: object["effectClass"]
            .as_str()
            .unwrap()
            .trim()
            .to_uppercase(),
        target: object["target"].as_str().unwrap().trim().to_owned(),
        arguments,
    })
}

use sha2::Digest as _;

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Value {
        serde_json::json!({"repositoryRevision": "rev1", "digest": "sha256:aaaa"})
    }

    #[test]
    fn imported_artifact_receipt_succeeds_for_bound_artifact() {
        let artifact = serde_json::json!({
            "binding": binding(),
            "path": "codeql.sarif",
            "digest": "sha256:bbbb",
            "bytes": 42,
            "mediaType": "application/sarif+json",
        });
        let receipt = imported_artifact_receipt("codeql", &artifact, &binding()).unwrap();
        assert_eq!(receipt["kind"], "legion-imported-artifact-receipt");
        assert_eq!(receipt["status"], "pass");
        assert_eq!(receipt["complete"], true);
        assert_eq!(receipt["artifact"]["path"], "codeql.sarif");
        assert_eq!(receipt["artifact"]["digest"], "sha256:bbbb");
        assert_eq!(receipt["artifact"]["bytes"], 42);
    }

    #[test]
    fn imported_artifact_receipt_rejects_binding_mismatch() {
        let artifact = serde_json::json!({
            "binding": {"repositoryRevision": "rev-other", "digest": "sha256:aaaa"},
            "path": "codeql.sarif",
            "digest": "sha256:bbbb",
        });
        let error = imported_artifact_receipt("codeql", &artifact, &binding()).unwrap_err();
        assert_eq!(
            error,
            ExecutorPortError::BindingMismatch("imported artifact".into())
        );
    }

    #[test]
    fn imported_artifact_receipt_rejects_missing_digest_or_path() {
        let artifact = serde_json::json!({"binding": binding(), "path": "codeql.sarif"});
        let error = imported_artifact_receipt("codeql", &artifact, &binding()).unwrap_err();
        assert_eq!(error, ExecutorPortError::MissingPathOrDigest);

        let artifact = serde_json::json!({"binding": binding(), "digest": "sha256:bbbb"});
        let error = imported_artifact_receipt("codeql", &artifact, &binding()).unwrap_err();
        assert_eq!(error, ExecutorPortError::MissingPathOrDigest);
    }

    #[test]
    fn ingest_imported_artifact_rejects_null_artifact() {
        let error = ingest_imported_artifact(&Value::Null, &binding()).unwrap_err();
        assert_eq!(
            error,
            ExecutorPortError::BindingMismatch("imported artifact".into())
        );
    }

    #[test]
    fn binding_digest_is_key_order_independent() {
        let a = serde_json::json!({"repositoryRevision": "r1", "digest": "sha256:aaaa"});
        let b = serde_json::json!({"digest": "sha256:aaaa", "repositoryRevision": "r1"});
        assert!(same_binding(Some(&a), Some(&b)));
    }

    #[test]
    fn binding_digest_normalizes_backslashes_in_strings() {
        let a = serde_json::json!({"path": "a/b"});
        let b = serde_json::json!({"path": "a\\b"});
        assert!(same_binding(Some(&a), Some(&b)));
    }

    #[test]
    fn normalize_executor_action_accepts_well_formed_action() {
        let value = serde_json::json!({
            "operation": " inspect ",
            "effectClass": " command_exec ",
            "target": " workspace ",
            "arguments": {"a": 1},
        });
        let action = normalize_executor_action(&value).unwrap();
        assert_eq!(action.operation, "inspect");
        assert_eq!(action.effect_class, "COMMAND_EXEC");
        assert_eq!(action.target, "workspace");
        assert_eq!(action.arguments.get("a"), Some(&Value::from(1)));
    }

    #[test]
    fn normalize_executor_action_defaults_missing_arguments_to_empty_object() {
        let value = serde_json::json!({
            "operation": "inspect",
            "effectClass": "COMMAND_EXEC",
            "target": "workspace",
        });
        let action = normalize_executor_action(&value).unwrap();
        assert!(action.arguments.is_empty());
    }

    #[test]
    fn normalize_executor_action_rejects_non_object() {
        let error = normalize_executor_action(&Value::Array(vec![])).unwrap_err();
        assert_eq!(
            error,
            malformed("executor action must be an object", "$")
        );
    }

    #[test]
    fn normalize_executor_action_rejects_unknown_field() {
        let value = serde_json::json!({
            "operation": "inspect",
            "effectClass": "COMMAND_EXEC",
            "target": "workspace",
            "extra": true,
        });
        let error = normalize_executor_action(&value).unwrap_err();
        assert_eq!(
            error,
            malformed("unknown executor action field: extra", "$.extra")
        );
    }

    #[test]
    fn normalize_executor_action_rejects_missing_required_field() {
        let value = serde_json::json!({
            "operation": "",
            "effectClass": "COMMAND_EXEC",
            "target": "workspace",
        });
        let error = normalize_executor_action(&value).unwrap_err();
        assert_eq!(
            error,
            malformed("executor action operation is required", "$.operation")
        );
    }
}
