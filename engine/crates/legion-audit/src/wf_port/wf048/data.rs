//! Port of `src/providers/runtime/web/data/index.mjs`
//! (`verifyDataExercise`) — chunk wf048.

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

use super::sanitize::sanitize_produced_artifact;
use super::shared::{binding_missing_gaps, denominator, exact_binding, finalize, redact, same_binding, unique_sorted};

const OPERATION_TYPES: &[&str] = &["query", "migration", "queue", "cache", "lifecycle", "restore"];
const RESULT_STATUSES: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];

fn is_sha256(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && value[7..].chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()))
}

fn nonempty_object(value: &Value) -> bool {
    matches!(value, Value::Object(m) if !m.is_empty())
}

fn get_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Port of `definitionGaps(definition, binding, dataset, schemaVersion)`.
fn definition_gaps(definition: &Value, binding: &Value, dataset: &str, schema_version: &str) -> Vec<String> {
    let id = get_str(definition, "id").unwrap_or("missing").to_string();
    let operation_type = get_str(definition, "operationType");
    if !definition.is_object() || !operation_type.map(|t| OPERATION_TYPES.contains(&t)).unwrap_or(false) {
        return vec![format!("data-case-definition-untyped:{id}")];
    }
    let mut gaps = Vec::new();
    let dataset_field = definition.get("dataset");
    if get_str(dataset_field.unwrap_or(&Value::Null), "id") != Some(dataset)
        || !is_sha256(get_str(dataset_field.unwrap_or(&Value::Null), "digest").unwrap_or(""))
    {
        gaps.push(format!("data-case-dataset-binding-invalid:{id}"));
    }
    let schema_field = definition.get("schema");
    if get_str(schema_field.unwrap_or(&Value::Null), "version") != Some(schema_version)
        || !is_sha256(get_str(schema_field.unwrap_or(&Value::Null), "digest").unwrap_or(""))
    {
        gaps.push(format!("data-case-schema-binding-invalid:{id}"));
    }
    let engine = definition.get("engine");
    let engine_name = get_str(engine.unwrap_or(&Value::Null), "name");
    let engine_version = get_str(engine.unwrap_or(&Value::Null), "version");
    let engine_digest = get_str(engine.unwrap_or(&Value::Null), "digest").unwrap_or("");
    if engine_name.map(|s| s.is_empty()).unwrap_or(true) || engine_version.map(|s| s.is_empty()).unwrap_or(true) || !is_sha256(engine_digest) {
        gaps.push(format!("data-case-engine-binding-invalid:{id}"));
    }
    let isolation = definition.get("isolation");
    let isolation_id = get_str(isolation.unwrap_or(&Value::Null), "id");
    let isolation_environment = get_str(isolation.unwrap_or(&Value::Null), "environment");
    let isolation_binding = isolation.and_then(|i| i.get("binding")).cloned().unwrap_or(json!({}));
    if isolation_id.map(str::is_empty).unwrap_or(true)
        || isolation_environment != binding.get("environment").and_then(Value::as_str)
        || !same_binding(binding, &isolation_binding)
    {
        gaps.push(format!("data-case-isolation-binding-invalid:{id}"));
    }
    let cleanup = definition.get("cleanupBinding");
    let cleanup_binding = cleanup.and_then(|c| c.get("binding")).cloned().unwrap_or(json!({}));
    if get_str(cleanup.unwrap_or(&Value::Null), "datasetId") != Some(dataset)
        || get_str(cleanup.unwrap_or(&Value::Null), "schemaVersion") != Some(schema_version)
        || get_str(cleanup.unwrap_or(&Value::Null), "environment") != binding.get("environment").and_then(Value::as_str)
        || !same_binding(binding, &cleanup_binding)
    {
        gaps.push(format!("data-case-cleanup-binding-invalid:{id}"));
    }
    let op = operation_type.unwrap_or_default();
    if op == "query" && !is_sha256(get_str(definition, "statementDigest").unwrap_or("")) {
        gaps.push(format!("data-case-query-contract-invalid:{id}"));
    }
    if op == "migration"
        && (!matches!(definition.get("fromSchemaVersion"), Some(Value::String(_)))
            || !matches!(definition.get("toSchemaVersion"), Some(Value::String(_)))
            || !is_sha256(get_str(definition, "migrationDigest").unwrap_or("")))
    {
        gaps.push(format!("data-case-migration-contract-invalid:{id}"));
    }
    if op == "queue" && (get_str(definition, "queueName").map(str::is_empty).unwrap_or(true) || get_str(definition, "messageId").map(str::is_empty).unwrap_or(true)) {
        gaps.push(format!("data-case-queue-contract-invalid:{id}"));
    }
    if op == "cache" {
        let consistency = get_str(definition, "consistency");
        if get_str(definition, "cacheKey").map(str::is_empty).unwrap_or(true) || !consistency.map(|c| c == "eventual" || c == "strong").unwrap_or(false) {
            gaps.push(format!("data-case-cache-contract-invalid:{id}"));
        }
    }
    if op == "lifecycle" {
        let phase = get_str(definition, "phase");
        if !phase.map(|p| ["create", "delete", "read", "update"].contains(&p)).unwrap_or(false) {
            gaps.push(format!("data-case-lifecycle-contract-invalid:{id}"));
        }
    }
    if op == "restore" && !is_sha256(get_str(definition, "restorePointDigest").unwrap_or("")) {
        gaps.push(format!("data-case-restore-contract-invalid:{id}"));
    }
    gaps
}

/// Port of `artifactResult(artifact, binding, definition, dataset, schemaVersion)`.
fn artifact_result(artifact: &Value, binding: &Value, definition: &Value, dataset: &str, schema_version: &str) -> (Value, bool, bool) {
    let produced = sanitize_produced_artifact(artifact);
    let engine_version = definition.get("engine").and_then(|e| e.get("version"));
    let artifact_binding = artifact.get("binding").cloned().unwrap_or(json!({}));
    let valid = produced.valid
        && artifact.get("kind").and_then(Value::as_str) == Some("data-result")
        && artifact.get("caseId") == definition.get("id")
        && artifact.get("datasetId").and_then(Value::as_str) == Some(dataset)
        && artifact.get("schemaVersion").and_then(Value::as_str) == Some(schema_version)
        && artifact.get("engineVersion") == engine_version
        && same_binding(binding, &artifact_binding);
    (produced.artifact, valid, produced.sensitive)
}

/// Adapter equivalent of the JS `{ exercise, cleanup }` object passed into
/// `verifyDataExercise`. `exercise` corresponds to `adapter.exercise(...)`
/// and `cleanup` to `adapter.cleanup(...)`.
#[async_trait]
pub trait DataExerciseAdapter {
    async fn exercise(&self, binding: &Value, dataset: &str, schema_version: &str, cases: &[Value]) -> Value;
    async fn cleanup(&self, binding: &Value, dataset: &str, schema_version: &str) -> Result<Value, Value>;
    /// Port of `typeof adapter.exercise !== 'function'` / cleanup-missing
    /// checks: an adapter that is entirely absent (JS default `adapter = {}`).
    fn is_present(&self) -> bool {
        true
    }
}

pub struct MissingAdapter;

#[async_trait]
impl DataExerciseAdapter for MissingAdapter {
    async fn exercise(&self, _binding: &Value, _dataset: &str, _schema_version: &str, _cases: &[Value]) -> Value {
        Value::Null
    }
    async fn cleanup(&self, _binding: &Value, _dataset: &str, _schema_version: &str) -> Result<Value, Value> {
        Ok(json!({}))
    }
    fn is_present(&self) -> bool {
        false
    }
}

/// Port of `verifyDataExercise({ binding, dataset, schemaVersion, adapter, cases })`.
pub async fn verify_data_exercise(
    binding: &Value,
    dataset: Option<&str>,
    schema_version: Option<&str>,
    adapter: &dyn DataExerciseAdapter,
    cases: &Value,
) -> Value {
    let dataset = dataset.unwrap_or("");
    let schema_version_str = schema_version.unwrap_or("");
    let case_list: Vec<Value> = cases.as_array().cloned().unwrap_or_default();
    let definitions: Vec<Value> = case_list
        .iter()
        .map(|item| match item {
            Value::String(s) => json!({"id": s}),
            Value::Object(_) => item.clone(),
            _ => json!({}),
        })
        .collect();
    let case_ids: Vec<Option<String>> = definitions.iter().map(|d| get_str(d, "id").map(str::to_string)).collect();
    let mut ids: Vec<String> = case_ids.iter().flatten().cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    ids.sort();

    let mut execution_gaps: Vec<String> = definitions.iter().flat_map(|d| definition_gaps(d, binding, dataset, schema_version_str)).collect();
    if !matches!(cases, Value::Array(_)) {
        execution_gaps.push("data-cases-invalid".to_string());
    }
    if binding.get("environment").and_then(Value::as_str) == Some("production") {
        execution_gaps.push("production-effect-forbidden".to_string());
    }
    if definitions.iter().any(|d| d.get("destructive") == Some(&Value::Bool(true))) {
        execution_gaps.push("destructive-effect-forbidden".to_string());
    }
    let preflight_invalid_now = !exact_binding(binding).gaps.is_empty()
        || dataset.is_empty()
        || schema_version_str.is_empty()
        || definitions.is_empty()
        || ids.len() != definitions.len()
        || !execution_gaps.is_empty();
    if preflight_invalid_now {
        execution_gaps.push("data-preflight-invalid".to_string());
    }
    let preflight_invalid = execution_gaps.iter().any(|g| g == "data-preflight-invalid");

    let mut receipts: Vec<Value> = Vec::new();
    let mut adapter_status = "unproven".to_string();
    let mut cleanup: Value = json!({"status": "unproven", "residualDamage": []});

    if preflight_invalid {
        receipts = ids.iter().map(|id| json!({"id": id, "status": "blocked", "terminal": true, "reason": "data-preflight-invalid"})).collect();
        adapter_status = "blocked".to_string();
        cleanup = json!({"status": "blocked", "reason": "data-preflight-invalid", "residualDamage": []});
    } else {
        let mut exercise_started = false;
        if !adapter.is_present() {
            execution_gaps.push("adapter-exercise-missing".to_string());
            receipts.extend(ids.iter().map(|id| json!({"id": id, "status": "unproven", "terminal": true, "reason": "adapter-missing"})));
        } else {
            exercise_started = true;
            let result = adapter.exercise(binding, dataset, schema_version_str, &definitions).await;
            let reported_status = get_str(&result, "status");
            if reported_status.map(|s| RESULT_STATUSES.contains(&s)).unwrap_or(false) {
                adapter_status = reported_status.unwrap().to_string();
            } else {
                adapter_status = "error".to_string();
                execution_gaps.push(format!("adapter-status-invalid:{}", reported_status.unwrap_or("missing")));
            }
            if result.get("terminal") != Some(&Value::Bool(true)) {
                execution_gaps.push("adapter-result-nonterminal".to_string());
                adapter_status = "error".to_string();
            }
            let rows: Vec<Value> = result.get("cases").and_then(Value::as_array).cloned().unwrap_or_default();
            let mut grouped: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
            for row in &rows {
                let id = get_str(row, "id").unwrap_or_default().to_string();
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
            for id in &ids {
                let row = match grouped.get(id).and_then(|v| v.first()) {
                    Some(r) => *r,
                    None => continue,
                };
                let definition = definitions.iter().find(|d| get_str(d, "id") == Some(id.as_str())).cloned().unwrap_or(json!({}));
                let terminal = row.get("terminal") == Some(&Value::Bool(true));
                let status_valid = get_str(row, "status").map(|s| RESULT_STATUSES.contains(&s)).unwrap_or(false);
                if !terminal {
                    execution_gaps.push(format!("data-case-nonterminal:{id}"));
                }
                if !status_valid {
                    execution_gaps.push(format!("data-case-status-invalid:{id}"));
                }
                let row_binding = row.get("binding").cloned().unwrap_or(json!({}));
                if !same_binding(binding, &row_binding) {
                    execution_gaps.push(format!("data-case-result-binding-mismatch:{id}"));
                }
                if row.get("operationType") != definition.get("operationType") {
                    execution_gaps.push(format!("data-case-operation-mismatch:{id}"));
                }
                if !nonempty_object(row.get("observed").unwrap_or(&Value::Null)) {
                    execution_gaps.push(format!("data-case-observed-invalid:{id}"));
                }
                if !nonempty_object(row.get("durableResult").unwrap_or(&Value::Null)) {
                    execution_gaps.push(format!("data-case-durable-result-invalid:{id}"));
                }
                let raw_artifacts: Vec<Value> = row.get("artifacts").and_then(Value::as_array).cloned().unwrap_or_default();
                let artifact_results: Vec<(Value, bool, bool)> = raw_artifacts
                    .iter()
                    .map(|a| artifact_result(a, binding, &definition, dataset, schema_version_str))
                    .collect();
                let artifacts: Vec<Value> = artifact_results.iter().filter(|(_, valid, _)| *valid).map(|(a, _, _)| a.clone()).collect();
                if artifact_results.is_empty() || artifact_results.iter().any(|(_, valid, _)| !valid) {
                    execution_gaps.push(format!("data-case-artifacts-invalid:{id}"));
                }
                if artifact_results.iter().any(|(_, _, sensitive)| *sensitive) {
                    execution_gaps.push(format!("data-case-artifact-sensitive:{id}"));
                }
                receipts.push(json!({
                    "id": id,
                    "operationType": definition.get("operationType").cloned().unwrap_or(Value::Null),
                    "status": if terminal && status_valid { row.get("status").cloned().unwrap_or(Value::Null) } else { Value::String("error".to_string()) },
                    "terminal": true,
                    "observed": redact(row.get("observed").unwrap_or(&Value::Null)),
                    "durableResult": redact(row.get("durableResult").unwrap_or(&Value::Null)),
                    "artifacts": artifacts,
                }));
            }
        }

        if exercise_started {
            match adapter.cleanup(binding, dataset, schema_version_str).await {
                Ok(cleanup_value) => {
                    // Port of `{ status: 'pass', ...redact(await adapter.cleanup(...)) }`:
                    // the base `status: 'pass'` is overridden if the
                    // (redacted) adapter result carries its own `status`.
                    let redacted = redact(&cleanup_value);
                    let mut merged = Map::new();
                    merged.insert("status".to_string(), Value::String("pass".to_string()));
                    if let Value::Object(map) = redacted {
                        for (k, v) in map {
                            merged.insert(k, v);
                        }
                    }
                    cleanup = Value::Object(merged);
                }
                Err(error_value) => {
                    let message = get_str(&error_value, "message").unwrap_or("adapter cleanup error").to_string();
                    let residual = error_value.get("residualDamage").and_then(Value::as_array).cloned().unwrap_or_default();
                    cleanup = json!({"status": "error", "error": redact(&Value::String(message)), "residualDamage": redact(&Value::Array(residual))});
                    execution_gaps.push("cleanup-error".to_string());
                }
            }
        }
    }

    let receipt_ids: Vec<String> = receipts.iter().filter_map(|r| get_str(r, "id").map(str::to_string)).collect();
    let counts = denominator(&ids, &receipt_ids, &[]);

    let mut gaps = binding_missing_gaps(binding);
    gaps.extend(execution_gaps);
    if case_list.is_empty() {
        gaps.push("data-case-denominator-empty".to_string());
    }
    if ids.len() != case_list.len() {
        gaps.push("data-case-denominator-duplicate".to_string());
    }
    if dataset.is_empty() {
        gaps.push("dataset-unbound".to_string());
    }
    if schema_version_str.is_empty() {
        gaps.push("schema-version-unbound".to_string());
    }
    let cleanup_status = get_str(&cleanup, "status").unwrap_or("unproven").to_string();
    if cleanup_status != "pass" {
        gaps.push("cleanup-unproven".to_string());
    }
    if cleanup_status == "pass" {
        let cleanup_binding = cleanup.get("binding").cloned().unwrap_or(json!({}));
        if get_str(&cleanup, "datasetId") != Some(dataset)
            || get_str(&cleanup, "schemaVersion") != Some(schema_version_str)
            || get_str(&cleanup, "environment") != binding.get("environment").and_then(Value::as_str)
            || !same_binding(binding, &cleanup_binding)
        {
            gaps.push("cleanup-binding-mismatch".to_string());
        }
    }
    if cleanup.get("residualDamage").and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false) {
        gaps.push("cleanup-residual-damage".to_string());
    }
    gaps.extend(counts.missing.iter().map(|id| format!("data-case-missing:{id}")));

    let mut statuses: Vec<&str> = vec![adapter_status.as_str(), cleanup_status.as_str()];
    statuses.extend(receipts.iter().filter_map(|r| get_str(r, "status")));
    let status = if statuses.contains(&"error") {
        "error"
    } else if statuses.contains(&"fail") {
        "fail"
    } else if statuses.contains(&"blocked") {
        "blocked"
    } else if statuses.contains(&"partial") {
        "partial"
    } else if !gaps.is_empty() || statuses.contains(&"unproven") {
        "unproven"
    } else {
        "pass"
    };

    let mut out = Map::new();
    out.insert("status".to_string(), Value::String(status.to_string()));
    out.insert("terminal".to_string(), Value::Bool(true));
    out.insert("binding".to_string(), binding.clone());
    out.insert("dataset".to_string(), Value::String(dataset.to_string()));
    out.insert("schemaVersion".to_string(), Value::String(schema_version_str.to_string()));
    out.insert("caseDefinitions".to_string(), Value::Array(definitions));
    out.insert("denominator".to_string(), counts.to_value());
    out.insert("receipts".to_string(), Value::Array(receipts));
    out.insert("cleanup".to_string(), cleanup);
    out.insert("coverageGaps".to_string(), Value::Array(unique_sorted(gaps).into_iter().map(Value::String).collect()));

    finalize("legion-web-data-exercise", Value::Object(out))
}
