//! Port of `src/providers/runtime/web/data/index.mjs` (`verifyDataExercise`)
//! and `src/providers/runtime/service/data/index.mjs` (`verifyServiceData`,
//! this chunk's assigned file). `verifyServiceData` is a thin wrapper over
//! `verifyDataExercise` — it is not ported by any earlier wf chunk (`git
//! grep` found no `verifyServiceData`/`verify_service_data` hits in
//! `engine/`) — so `verifyDataExercise` is faithfully ported here too, as
//! an internal dependency, since `verifyServiceData`'s behaviour is
//! entirely defined by it.
//!
//! JS's `adapter.exercise`/`adapter.cleanup` are async functions supplied
//! by the caller. This port models the adapter as a synchronous closure
//! pair (`DataAdapter`) returning `serde_json::Value` shapes identical to
//! the JS adapter's resolved/rejected values — the verification logic
//! itself has no intrinsic asynchrony, only the (out-of-scope, effectful)
//! exercise call does.

use super::shared::{denominator, exact_binding, finalize, redact, same_binding};
use serde_json::{Map, Value};

const OPERATION_TYPES: &[&str] = &["query", "migration", "queue", "cache", "lifecycle", "restore"];
const RESULT_STATUSES: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];

fn sha256_re() -> regex::Regex {
    regex::Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap()
}

fn is_sha256(value: &Value) -> bool {
    value.as_str().is_some_and(|s| sha256_re().is_match(s))
}

fn nonempty_object(value: &Value) -> bool {
    value.as_object().is_some_and(|m| !m.is_empty())
}

fn str_field<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

/// Result of `sanitizeProducedArtifact` + the extra validity checks
/// `artifactResult` layers on top, from `data/index.mjs`.
struct ArtifactResult {
    valid: bool,
    sensitive: bool,
    artifact: Value,
}

/// This crate has no native port of `sanitizeProducedArtifact` from
/// `lib/platform/artifact-sanitize.mjs` visible to this module (it is
/// imported, not owned, by the JS source; wf047 does not own that file).
/// We model its externally-observable contract directly: an artifact
/// object is "sanitized" if it carries no unredacted sensitive-looking
/// string fields (mirrors `redact`'s own sensitive-key/value sweep), the
/// sanitized artifact is `redact(artifact)`, and `sensitive` is true if
/// redaction changed anything.
fn sanitize_produced_artifact(artifact: &Value) -> (bool, Value) {
    let redacted = redact(artifact, "");
    let sensitive = redacted != *artifact;
    (sensitive, redacted)
}

fn artifact_result(
    artifact: &Value,
    binding: &Value,
    definition: &Value,
    dataset: &str,
    schema_version: &str,
) -> ArtifactResult {
    let (sensitive, sanitized) = sanitize_produced_artifact(artifact);
    let definition_id = str_field(definition, "id");
    let engine_version = definition.get("engine").and_then(|e| e.get("version"));
    let valid = artifact.get("kind").and_then(Value::as_str) == Some("data-result")
        && artifact.get("caseId").and_then(Value::as_str) == definition_id
        && artifact.get("datasetId").and_then(Value::as_str) == Some(dataset)
        && artifact.get("schemaVersion").and_then(Value::as_str) == Some(schema_version)
        && artifact.get("engineVersion") == engine_version
        && same_binding(binding, artifact.get("binding").unwrap_or(&Value::Null));
    ArtifactResult { valid, sensitive, artifact: sanitized }
}

fn definition_gaps(definition: &Value, binding: &Value, dataset: &str, schema_version: &str) -> Vec<String> {
    let id = str_field(definition, "id").unwrap_or("missing");
    if !definition.is_object()
        || !OPERATION_TYPES.contains(&definition.get("operationType").and_then(Value::as_str).unwrap_or(""))
    {
        return vec![format!("data-case-definition-untyped:{id}")];
    }
    let mut gaps = Vec::new();
    let dataset_obj = definition.get("dataset");
    if dataset_obj.and_then(|d| d.get("id")).and_then(Value::as_str) != Some(dataset)
        || !dataset_obj.and_then(|d| d.get("digest")).is_some_and(|d| is_sha256(d))
    {
        gaps.push(format!("data-case-dataset-binding-invalid:{id}"));
    }
    let schema_obj = definition.get("schema");
    if schema_obj.and_then(|s| s.get("version")).and_then(Value::as_str) != Some(schema_version)
        || !schema_obj.and_then(|s| s.get("digest")).is_some_and(is_sha256)
    {
        gaps.push(format!("data-case-schema-binding-invalid:{id}"));
    }
    let engine = definition.get("engine");
    let engine_name = engine.and_then(|e| e.get("name")).and_then(Value::as_str);
    let engine_ver = engine.and_then(|e| e.get("version")).and_then(Value::as_str);
    if engine_name.unwrap_or("").is_empty()
        || engine_ver.unwrap_or("").is_empty()
        || !engine.and_then(|e| e.get("digest")).is_some_and(is_sha256)
    {
        gaps.push(format!("data-case-engine-binding-invalid:{id}"));
    }
    let isolation = definition.get("isolation");
    let isolation_id = isolation.and_then(|i| i.get("id")).and_then(Value::as_str);
    let isolation_env = isolation.and_then(|i| i.get("environment")).and_then(Value::as_str);
    let binding_env = binding.get("environment").and_then(Value::as_str);
    if isolation_id.unwrap_or("").is_empty()
        || isolation_env != binding_env
        || !same_binding(binding, isolation.and_then(|i| i.get("binding")).unwrap_or(&Value::Null))
    {
        gaps.push(format!("data-case-isolation-binding-invalid:{id}"));
    }
    let cleanup = definition.get("cleanupBinding");
    if cleanup.and_then(|c| c.get("datasetId")).and_then(Value::as_str) != Some(dataset)
        || cleanup.and_then(|c| c.get("schemaVersion")).and_then(Value::as_str) != Some(schema_version)
        || cleanup.and_then(|c| c.get("environment")).and_then(Value::as_str) != binding_env
        || !same_binding(binding, cleanup.and_then(|c| c.get("binding")).unwrap_or(&Value::Null))
    {
        gaps.push(format!("data-case-cleanup-binding-invalid:{id}"));
    }
    let op_type = definition.get("operationType").and_then(Value::as_str).unwrap_or("");
    match op_type {
        "query" => {
            if !definition.get("statementDigest").is_some_and(is_sha256) {
                gaps.push(format!("data-case-query-contract-invalid:{id}"));
            }
        }
        "migration" => {
            if !definition.get("fromSchemaVersion").is_some_and(Value::is_string)
                || !definition.get("toSchemaVersion").is_some_and(Value::is_string)
                || !definition.get("migrationDigest").is_some_and(is_sha256)
            {
                gaps.push(format!("data-case-migration-contract-invalid:{id}"));
            }
        }
        "queue" => {
            let queue_name = definition.get("queueName").and_then(Value::as_str).unwrap_or("");
            let message_id = definition.get("messageId").and_then(Value::as_str).unwrap_or("");
            if queue_name.is_empty() || message_id.is_empty() {
                gaps.push(format!("data-case-queue-contract-invalid:{id}"));
            }
        }
        "cache" => {
            let cache_key = definition.get("cacheKey").and_then(Value::as_str).unwrap_or("");
            let consistency = definition.get("consistency").and_then(Value::as_str).unwrap_or("");
            if cache_key.is_empty() || !["eventual", "strong"].contains(&consistency) {
                gaps.push(format!("data-case-cache-contract-invalid:{id}"));
            }
        }
        "lifecycle" => {
            let phase = definition.get("phase").and_then(Value::as_str).unwrap_or("");
            if !["create", "delete", "read", "update"].contains(&phase) {
                gaps.push(format!("data-case-lifecycle-contract-invalid:{id}"));
            }
        }
        "restore" => {
            if !definition.get("restorePointDigest").is_some_and(is_sha256) {
                gaps.push(format!("data-case-restore-contract-invalid:{id}"));
            }
        }
        _ => {}
    }
    gaps
}

/// Port of the `adapter` parameter: `{ exercise, cleanup }`.
pub struct DataAdapter<'a> {
    pub exercise: Option<Box<dyn FnMut(&Value) -> Result<Value, Value> + 'a>>,
    pub cleanup: Option<Box<dyn FnMut(&Value) -> Result<Value, Value> + 'a>>,
}

impl<'a> Default for DataAdapter<'a> {
    fn default() -> Self {
        Self { exercise: None, cleanup: None }
    }
}

/// Port of `verifyDataExercise(input)`.
pub fn verify_data_exercise(
    binding: &Value,
    dataset: Option<&str>,
    schema_version: Option<&str>,
    adapter: &mut DataAdapter,
    cases: &Value,
) -> Value {
    let cases_is_array = cases.is_array();
    let case_list: Vec<Value> = cases.as_array().cloned().unwrap_or_default();

    let definitions: Vec<Value> = case_list
        .iter()
        .map(|item| match item {
            Value::String(s) => {
                let mut m = Map::new();
                m.insert("id".to_string(), Value::String(s.clone()));
                Value::Object(m)
            }
            Value::Object(_) => item.clone(),
            _ => Value::Object(Map::new()),
        })
        .collect();

    let case_ids: Vec<Option<String>> = definitions
        .iter()
        .map(|d| d.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut ids: Vec<String> = case_ids.iter().flatten().cloned().collect();
    ids.sort();
    ids.dedup();

    let mut receipts: Vec<Value> = Vec::new();
    let mut adapter_status = "unproven".to_string();
    let mut exercise_started = false;

    let mut execution_gaps: Vec<String> = definitions
        .iter()
        .flat_map(|d| definition_gaps(d, binding, dataset.unwrap_or(""), schema_version.unwrap_or("")))
        .collect();

    let mut cleanup: Value = serde_json::json!({ "status": "unproven", "residualDamage": [] });

    if !cases_is_array {
        execution_gaps.push("data-cases-invalid".to_string());
    }
    if binding.get("environment").and_then(Value::as_str) == Some("production") {
        execution_gaps.push("production-effect-forbidden".to_string());
    }
    if definitions.iter().any(|d| d.get("destructive") == Some(&Value::Bool(true))) {
        execution_gaps.push("destructive-effect-forbidden".to_string());
    }
    let preflight_invalid = !exact_binding(binding).gaps.is_empty()
        || dataset.is_none_or(str::is_empty)
        || schema_version.is_none_or(str::is_empty)
        || definitions.is_empty()
        || ids.len() != definitions.len()
        || !execution_gaps.is_empty();
    if preflight_invalid {
        execution_gaps.push("data-preflight-invalid".to_string());
    }

    if preflight_invalid {
        receipts = ids
            .iter()
            .map(|id| serde_json::json!({ "id": id, "status": "blocked", "terminal": true, "reason": "data-preflight-invalid" }))
            .collect();
        adapter_status = "blocked".to_string();
        cleanup = serde_json::json!({ "status": "blocked", "reason": "data-preflight-invalid", "residualDamage": [] });
    } else {
        let exercise_input = serde_json::json!({
            "binding": binding, "dataset": dataset, "schemaVersion": schema_version, "cases": definitions,
        });
        match adapter.exercise.as_mut() {
            None => {
                execution_gaps.push("adapter-exercise-missing".to_string());
                receipts.extend(ids.iter().map(|id| {
                    serde_json::json!({ "id": id, "status": "unproven", "terminal": true, "reason": "adapter-missing" })
                }));
            }
            Some(exercise) => {
                exercise_started = true;
                match exercise(&exercise_input) {
                    Err(error) => {
                        adapter_status = "error".to_string();
                        let message = error.get("message").and_then(Value::as_str).map(str::to_string)
                            .unwrap_or_else(|| error.to_string());
                        receipts.extend(ids.iter().map(|id| {
                            serde_json::json!({ "id": id, "status": "error", "terminal": true, "error": redact(&Value::String(message.clone()), "") })
                        }));
                    }
                    Ok(result) => {
                        let reported_status = result.get("status").and_then(Value::as_str);
                        adapter_status = reported_status
                            .filter(|s| RESULT_STATUSES.contains(s))
                            .unwrap_or("error")
                            .to_string();
                        if !reported_status.is_some_and(|s| RESULT_STATUSES.contains(&s)) {
                            execution_gaps.push(format!("adapter-status-invalid:{}", reported_status.unwrap_or("missing")));
                        }
                        if result.get("terminal") != Some(&Value::Bool(true)) {
                            execution_gaps.push("adapter-result-nonterminal".to_string());
                            adapter_status = "error".to_string();
                        }
                        let rows: Vec<Value> = result.get("cases").and_then(Value::as_array).cloned().unwrap_or_default();
                        let mut grouped: std::collections::BTreeMap<String, Vec<&Value>> = std::collections::BTreeMap::new();
                        for row in &rows {
                            let id = row.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                            grouped.entry(id).or_default().push(row);
                        }
                        for (id, matches) in &grouped {
                            if !ids.contains(id) {
                                execution_gaps.push(format!("data-case-unplanned:{id}"));
                            }
                            if matches.len() > 1 {
                                execution_gaps.push(format!("data-case-duplicate:{id}"));
                            }
                        }
                        receipts = ids
                            .iter()
                            .filter_map(|id| {
                                let row = grouped.get(id)?.first().copied()?;
                                let definition = definitions
                                    .iter()
                                    .find(|d| d.get("id").and_then(Value::as_str) == Some(id.as_str()))
                                    .cloned()
                                    .unwrap_or_else(|| Value::Object(Map::new()));
                                let terminal = row.get("terminal") == Some(&Value::Bool(true));
                                let row_status = row.get("status").and_then(Value::as_str).unwrap_or("");
                                let status_valid = RESULT_STATUSES.contains(&row_status);
                                if !terminal {
                                    execution_gaps.push(format!("data-case-nonterminal:{id}"));
                                }
                                if !status_valid {
                                    execution_gaps.push(format!("data-case-status-invalid:{id}"));
                                }
                                if !same_binding(binding, row.get("binding").unwrap_or(&Value::Null)) {
                                    execution_gaps.push(format!("data-case-result-binding-mismatch:{id}"));
                                }
                                if row.get("operationType") != definition.get("operationType") {
                                    execution_gaps.push(format!("data-case-operation-mismatch:{id}"));
                                }
                                if !row.get("observed").is_some_and(nonempty_object) {
                                    execution_gaps.push(format!("data-case-observed-invalid:{id}"));
                                }
                                if !row.get("durableResult").is_some_and(nonempty_object) {
                                    execution_gaps.push(format!("data-case-durable-result-invalid:{id}"));
                                }
                                let raw_artifacts: Vec<Value> = row.get("artifacts").and_then(Value::as_array).cloned().unwrap_or_default();
                                let artifact_results: Vec<ArtifactResult> = raw_artifacts
                                    .iter()
                                    .map(|a| artifact_result(a, binding, &definition, dataset.unwrap_or(""), schema_version.unwrap_or("")))
                                    .collect();
                                let artifacts: Vec<Value> = artifact_results.iter().filter(|r| r.valid).map(|r| r.artifact.clone()).collect();
                                if artifact_results.is_empty() || artifact_results.iter().any(|r| !r.valid) {
                                    execution_gaps.push(format!("data-case-artifacts-invalid:{id}"));
                                }
                                if artifact_results.iter().any(|r| r.sensitive) {
                                    execution_gaps.push(format!("data-case-artifact-sensitive:{id}"));
                                }
                                Some(serde_json::json!({
                                    "id": id,
                                    "operationType": definition.get("operationType").cloned().unwrap_or(Value::Null),
                                    "status": if terminal && status_valid { Value::String(row_status.to_string()) } else { Value::String("error".to_string()) },
                                    "terminal": true,
                                    "observed": redact(row.get("observed").unwrap_or(&Value::Null), ""),
                                    "durableResult": redact(row.get("durableResult").unwrap_or(&Value::Null), ""),
                                    "artifacts": artifacts,
                                }))
                            })
                            .collect();
                    }
                }
            }
        }

        if exercise_started {
            if let Some(cleanup_fn) = adapter.cleanup.as_mut() {
                let cleanup_input = serde_json::json!({ "binding": binding, "dataset": dataset, "schemaVersion": schema_version });
                match cleanup_fn(&cleanup_input) {
                    Ok(result) => {
                        let mut obj = result.as_object().cloned().unwrap_or_default();
                        let redacted = redact(&Value::Object(obj.clone()), "");
                        obj = redacted.as_object().cloned().unwrap_or_default();
                        obj.insert("status".to_string(), Value::String("pass".to_string()));
                        cleanup = Value::Object(obj);
                    }
                    Err(error) => {
                        let message = error.get("message").and_then(Value::as_str).map(str::to_string)
                            .unwrap_or_else(|| error.to_string());
                        let residual = error.get("residualDamage").and_then(Value::as_array).cloned().unwrap_or_default();
                        cleanup = serde_json::json!({
                            "status": "error",
                            "error": redact(&Value::String(message), ""),
                            "residualDamage": redact(&Value::Array(residual), ""),
                        });
                        execution_gaps.push("cleanup-error".to_string());
                    }
                }
            }
        }
    }

    let receipt_ids: Vec<String> = receipts.iter().filter_map(|r| r.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    let counts = denominator(&ids, &receipt_ids, &[]);
    let mut gaps: Vec<String> = exact_binding(binding).gaps.iter().map(|k| format!("binding-missing:{k}")).collect();
    gaps.extend(execution_gaps);
    if case_list.is_empty() {
        gaps.push("data-case-denominator-empty".to_string());
    }
    if ids.len() != case_list.len() {
        gaps.push("data-case-denominator-duplicate".to_string());
    }
    if dataset.is_none_or(str::is_empty) {
        gaps.push("dataset-unbound".to_string());
    }
    if schema_version.is_none_or(str::is_empty) {
        gaps.push("schema-version-unbound".to_string());
    }
    let cleanup_status = cleanup.get("status").and_then(Value::as_str).unwrap_or("");
    if cleanup_status != "pass" {
        gaps.push("cleanup-unproven".to_string());
    }
    if cleanup_status == "pass" {
        let binding_env = binding.get("environment").and_then(Value::as_str);
        if cleanup.get("datasetId").and_then(Value::as_str) != dataset
            || cleanup.get("schemaVersion").and_then(Value::as_str) != schema_version
            || cleanup.get("environment").and_then(Value::as_str) != binding_env
            || !same_binding(binding, cleanup.get("binding").unwrap_or(&Value::Null))
        {
            gaps.push("cleanup-binding-mismatch".to_string());
        }
    }
    if cleanup.get("residualDamage").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
        gaps.push("cleanup-residual-damage".to_string());
    }
    gaps.extend(counts.missing.iter().map(|id| format!("data-case-missing:{id}")));

    let mut statuses: std::collections::HashSet<String> = std::collections::HashSet::new();
    statuses.insert(adapter_status);
    statuses.insert(cleanup_status.to_string());
    for r in &receipts {
        if let Some(s) = r.get("status").and_then(Value::as_str) {
            statuses.insert(s.to_string());
        }
    }
    let status = if statuses.contains("error") {
        "error"
    } else if statuses.contains("fail") {
        "fail"
    } else if statuses.contains("blocked") {
        "blocked"
    } else if statuses.contains("partial") {
        "partial"
    } else if !gaps.is_empty() || statuses.contains("unproven") {
        "unproven"
    } else {
        "pass"
    };

    let mut sorted_gaps = gaps;
    sorted_gaps.sort();
    sorted_gaps.dedup();

    finalize(
        "legion-web-data-exercise",
        serde_json::json!({
            "status": status,
            "terminal": true,
            "binding": binding,
            "dataset": dataset,
            "schemaVersion": schema_version,
            "caseDefinitions": definitions,
            "denominator": counts.to_value(),
            "receipts": receipts,
            "cleanup": cleanup,
            "coverageGaps": sorted_gaps,
        }),
    )
}

/// Port of `verifyServiceData(input)` from
/// `src/providers/runtime/service/data/index.mjs`. Strips `digest`,
/// `kind`, and `schemaVersion` from the `verifyDataExercise` receipt and
/// re-wraps it via `finalize('legion-service-data-provider', ...)` with
/// `provider: 'runtime.service.data'` and `claimLevel: 'runtime'`.
pub fn verify_service_data(
    binding: &Value,
    dataset: Option<&str>,
    schema_version: Option<&str>,
    adapter: &mut DataAdapter,
    cases: &Value,
) -> Value {
    let exercise = verify_data_exercise(binding, dataset, schema_version, adapter, cases);
    let mut receipt = exercise.as_object().cloned().unwrap_or_default();
    receipt.remove("digest");
    receipt.remove("kind");
    receipt.remove("schemaVersion");
    let mut wrapped = Map::new();
    wrapped.insert("provider".to_string(), Value::String("runtime.service.data".to_string()));
    wrapped.insert("claimLevel".to_string(), Value::String("runtime".to_string()));
    for (k, v) in receipt {
        wrapped.insert(k, v);
    }
    finalize("legion-service-data-provider", Value::Object(wrapped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_binding() -> Value {
        let mut m = Map::new();
        for key in super::super::shared::BINDING_KEYS {
            m.insert(key.to_string(), Value::String(format!("{key}-v")));
        }
        m.insert("environment".to_string(), Value::String("staging".to_string()));
        Value::Object(m)
    }

    #[test]
    fn verify_service_data_blocks_on_empty_cases() {
        let binding = full_binding();
        let mut adapter = DataAdapter::default();
        let out = verify_service_data(&binding, Some("ds"), Some("v1"), &mut adapter, &Value::Array(vec![]));
        assert_eq!(out["status"], "unproven");
        assert!(!out.get("digest").is_some());
        assert!(!out.get("kind").is_some());
        assert_eq!(out["provider"], "runtime.service.data");
        assert_eq!(out["claimLevel"], "runtime");
    }

    #[test]
    fn verify_service_data_blocks_without_adapter() {
        let binding = full_binding();
        let mut adapter = DataAdapter::default();
        let cases = Value::Array(vec![Value::String("case-1".to_string())]);
        let out = verify_service_data(&binding, Some("ds"), Some("v1"), &mut adapter, &cases);
        // No adapter.exercise -> adapter-exercise-missing gap -> unproven.
        assert_eq!(out["status"], "unproven");
        let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(gaps.contains(&"adapter-exercise-missing"));
    }

    #[test]
    fn verify_service_data_production_environment_is_forbidden() {
        let mut m = Map::new();
        for key in super::super::shared::BINDING_KEYS {
            m.insert(key.to_string(), Value::String(format!("{key}-v")));
        }
        m.insert("environment".to_string(), Value::String("production".to_string()));
        let binding = Value::Object(m);
        let mut adapter = DataAdapter::default();
        let cases = Value::Array(vec![Value::String("case-1".to_string())]);
        let out = verify_service_data(&binding, Some("ds"), Some("v1"), &mut adapter, &cases);
        let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(gaps.contains(&"production-effect-forbidden"));
    }
}
