//! Native Rust port of the legacy JS browser / native-surface / service
//! runtime providers. Faithful port of:
//!
//! - `src/providers/runtime/browser/adapter.mjs`
//! - `src/providers/runtime/browser/index.mjs`
//! - `src/providers/runtime/native-surface/adapter.mjs`
//! - `src/providers/runtime/service/api/index.mjs`
//! - `src/providers/runtime/service/core/index.mjs`
//! - `src/providers/runtime/service/data/index.mjs`
//! - `src/providers/runtime/service/faults/index.mjs`
//!
//! No Membrane or Blueprint behaviour appeared in any of these seven files;
//! nothing was dropped for that reason.
//!
//! `service/api/index.mjs` and `service/data/index.mjs` in JS delegate their
//! actual exercise logic to `web/api/index.mjs` and `web/data/index.mjs`
//! (composed through `web/shared.mjs`'s `finalize`). None of those three
//! files are part of this port's owned file set (they belong to a different
//! packet and were not found under `engine/` by keyword search either).
//! This module therefore ports the *wrapping* behaviour of the two service
//! files faithfully: it accepts the already-computed exercise receipt (i.e.
//! whatever a native `web.api` / `web.data` provider produces) and performs
//! the same relabel-then-finalize step the JS wrappers perform. A local,
//! faithful port of the small pieces of `web/shared.mjs` needed for that
//! (`finalize`, `canonicalize`, `digest`, `exactBinding`) backs it.

use std::collections::BTreeSet;

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/* =======================================================================
 * web/shared.mjs (minimal faithful subset used by verify_service_api/data)
 * ===================================================================== */

const BINDING_KEYS: [&str; 10] = [
    "targetId",
    "environment",
    "actorId",
    "tenantId",
    "browser",
    "browserVersion",
    "viewport",
    "locale",
    "sourceRevision",
    "artifactDigest",
];

const SENSITIVE_KEYS: [&str; 16] = [
    "apikey",
    "apitoken",
    "authorization",
    "authorizationheader",
    "clientsecret",
    "cookie",
    "email",
    "password",
    "passwd",
    "phone",
    "privatekey",
    "secret",
    "sessioncookie",
    "setcookie",
    "token",
    "accesstoken",
];
const SENSITIVE_SUFFIXES: [&str; 9] = [
    "apikey",
    "authorization",
    "cookie",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "secretkey",
    "token",
];

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    SENSITIVE_KEYS.contains(&normalized.as_str())
        || SENSITIVE_SUFFIXES.iter().any(|suffix| normalized.ends_with(suffix))
}

fn opaque(kind: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{kind}:{value}").as_bytes());
    let digest = hasher.finalize();
    format!("opaque-{}", &hex::encode(digest)[..24])
}

/// Faithful port of `canonicalize` restricted to the JSON value space:
/// `serde_json::Value` has no `bigint`/`symbol`/`function`/`undefined`
/// variants and is a tree (not a graph), so the corresponding JS branches
/// (opaque-encoding those types, cycle detection) are unreachable here and
/// are intentionally not reproduced.
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
        other => other.clone(),
    }
}

fn digest_value(value: &Value) -> String {
    let canonical = canonicalize(value);
    let serialized = serde_json::to_string(&canonical).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`
fn is_valid_binding_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

struct ExactBindingResult {
    binding: Value,
    gaps: Vec<String>,
}

fn exact_binding(binding: &Value) -> ExactBindingResult {
    let source = match binding {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    let invalid: Vec<&str> = BINDING_KEYS
        .iter()
        .copied()
        .filter(|key| !matches!(source.get(*key), Some(Value::String(s)) if is_valid_binding_token(s)))
        .collect();

    let mut sorted_keys = BINDING_KEYS.to_vec();
    sorted_keys.sort();
    let mut normalized = Map::new();
    for key in sorted_keys {
        let value = if invalid.contains(&key) {
            let raw = source.get(key).cloned().unwrap_or(Value::Null);
            let canon = canonicalize(&raw);
            Value::String(opaque("binding", &serde_json::to_string(&canon).unwrap_or_default()))
        } else {
            source.get(key).cloned().unwrap_or(Value::Null)
        };
        normalized.insert(key.to_string(), value);
    }

    let extras: Vec<&String> = source.keys().filter(|key| !BINDING_KEYS.contains(&key.as_str())).collect();
    let mut gaps: Vec<String> = invalid.iter().map(|s| s.to_string()).collect();
    if extras.iter().any(|key| is_sensitive_key(key.as_str())) {
        gaps.push("binding-extra-sensitive".to_string());
    }
    if extras.iter().any(|key| !is_sensitive_key(key.as_str())) {
        gaps.push("binding-extra-undeclared".to_string());
    }

    ExactBindingResult {
        binding: Value::Object(normalized),
        gaps,
    }
}

fn normalize_bindings(value: &Value, key: &str, gaps: &mut Vec<String>) -> Value {
    if key == "binding" {
        let result = exact_binding(value);
        gaps.extend(result.gaps);
        return result.binding;
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| normalize_bindings(item, "", gaps)).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), normalize_bindings(&map[key], key, gaps));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Faithful port of `finalize(kind, value)`.
fn finalize(kind: &str, value: Value) -> Value {
    let mut binding_gaps: Vec<String> = Vec::new();
    let mut safe_value = normalize_bindings(&value, "", &mut binding_gaps);

    if !binding_gaps.is_empty() {
        if let Value::Object(ref mut map) = safe_value {
            map.insert("status".to_string(), json!("error"));
            map.insert("terminal".to_string(), json!(true));
            if map.contains_key("complete") {
                map.insert("complete".to_string(), json!(false));
            }
            if map.contains_key("proof") {
                map.insert("proof".to_string(), json!(false));
            }
            let mut existing: BTreeSet<String> = match map.get("coverageGaps") {
                Some(Value::Array(items)) => items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
                _ => BTreeSet::new(),
            };
            for gap in &binding_gaps {
                let entry = if gap.starts_with("binding-extra-") {
                    gap.clone()
                } else {
                    format!("binding-invalid:{gap}")
                };
                existing.insert(entry);
            }
            map.insert(
                "coverageGaps".to_string(),
                Value::Array(existing.into_iter().map(Value::String).collect()),
            );
        }
    }

    let mut merged = Map::new();
    merged.insert("schemaVersion".to_string(), json!(1));
    merged.insert("kind".to_string(), json!(kind));
    if let Value::Object(map) = safe_value {
        for (k, v) in map {
            merged.insert(k, v);
        }
    }
    let normalized = canonicalize(&Value::Object(merged));
    let digest = digest_value(&normalized);
    let mut result = match normalized {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    result.insert("digest".to_string(), json!(digest));
    Value::Object(result)
}

/* =======================================================================
 * browser/adapter.mjs
 * ===================================================================== */

/// `/authorization|cookie|password|token|secret|api[-_]?key/i`
fn key_matches_redaction_pattern(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("authorization")
        || lower.contains("cookie")
        || lower.contains("password")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("apikey")
        || lower.contains("api-key")
        || lower.contains("api_key")
}

fn redact_value(value: &Value, key: &str) -> Value {
    if key_matches_redaction_pattern(key) {
        return json!("[REDACTED]");
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| redact_value(item, "")).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), redact_value(v, k));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_)) | Some(Value::Object(_)) => true,
    }
}

fn is_true(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

fn is_false(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(false)))
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Faithful port of `buildBrowserSurfaceReceipt(spec, observation)`.
pub fn build_browser_surface_receipt(spec: &Value, observation: &Value) -> Value {
    let spec_obj = spec.as_object();
    let obs_obj = observation.as_object();

    let allowed_actions: BTreeSet<String> =
        string_array(spec_obj.and_then(|m| m.get("allowedActions"))).into_iter().collect();
    let allowed_destinations: BTreeSet<String> =
        string_array(spec_obj.and_then(|m| m.get("allowedDestinations"))).into_iter().collect();

    let actions = string_array(obs_obj.and_then(|m| m.get("actions")));
    let undeclared_actions: Vec<String> = actions.into_iter().filter(|a| !allowed_actions.contains(a)).collect();

    let requests: Vec<Value> = obs_obj
        .and_then(|m| m.get("requests"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let undeclared_destinations: Vec<Value> = requests
        .iter()
        .map(|r| r.get("destination").cloned().unwrap_or(Value::Null))
        .filter(|destination| match destination.as_str() {
            Some(s) => !allowed_destinations.contains(s),
            None => true,
        })
        .collect();

    let reached_meaningful_state = is_true(obs_obj.and_then(|m| m.get("reachedMeaningfulState")));
    let shallow = !reached_meaningful_state;
    let failed_launch = truthy(obs_obj.and_then(|m| m.get("failedLaunch")));
    let credentials_missing = truthy(obs_obj.and_then(|m| m.get("credentialsMissing")));
    let blocked = !undeclared_actions.is_empty() || !undeclared_destinations.is_empty() || failed_launch || credentials_missing;
    let ready = is_true(obs_obj.and_then(|m| m.get("ready")));
    let status = if blocked {
        "blocked"
    } else if !ready || shallow {
        "unproven"
    } else {
        "pass"
    };

    let console = obs_obj.and_then(|m| m.get("console")).cloned().unwrap_or(Value::Array(vec![]));
    let redacted_console = redact_value(&console, "");
    let redacted_requests: Vec<Value> = requests.iter().map(|r| redact_value(r, "")).collect();

    let mut coverage_gaps: Vec<Value> = Vec::new();
    if !ready {
        coverage_gaps.push(json!("readiness-unproven"));
    }
    if shallow {
        coverage_gaps.push(json!("shallow-traversal"));
    }

    json!({
        "schemaVersion": 1,
        "kind": "legion-runtime-receipt",
        "provider": "runtime.browser",
        "surfaceId": spec_obj.and_then(|m| m.get("surfaceId")).cloned().unwrap_or(Value::Null),
        "route": spec_obj.and_then(|m| m.get("route")).cloned().unwrap_or(Value::Null),
        "state": obs_obj.and_then(|m| m.get("state")).cloned().unwrap_or(json!("default")),
        "viewport": obs_obj.and_then(|m| m.get("viewport")).cloned().unwrap_or(Value::Null),
        "locale": obs_obj.and_then(|m| m.get("locale")).cloned().unwrap_or(Value::Null),
        "direction": obs_obj.and_then(|m| m.get("direction")).cloned().unwrap_or(Value::Null),
        "status": status,
        "complete": status == "pass",
        "shallow": shallow,
        "undeclaredActions": undeclared_actions,
        "undeclaredDestinations": undeclared_destinations,
        "console": redacted_console,
        "requests": redacted_requests,
        "performance": obs_obj.and_then(|m| m.get("performance")).cloned().unwrap_or(Value::Null),
        "processLifecycle": obs_obj.and_then(|m| m.get("processLifecycle")).cloned().unwrap_or(Value::Null),
        "recovery": obs_obj.and_then(|m| m.get("recovery")).cloned().unwrap_or(Value::Null),
        "coverageGaps": coverage_gaps,
        "binding": spec_obj.and_then(|m| m.get("binding")).cloned().unwrap_or(json!({})),
    })
}

/* =======================================================================
 * native-surface/adapter.mjs
 * ===================================================================== */

/// Faithful port of `buildNativeSurfaceReceipt(spec, observation)`.
pub fn build_native_surface_receipt(spec: &Value, observation: &Value) -> Value {
    let spec_obj = spec.as_object();
    let obs_obj = observation.as_object();

    let allowed: BTreeSet<String> = string_array(spec_obj.and_then(|m| m.get("allowedActions"))).into_iter().collect();
    let actions = string_array(obs_obj.and_then(|m| m.get("actions")));
    let undeclared_actions: Vec<String> = actions.into_iter().filter(|a| !allowed.contains(a)).collect();

    let bridge_unavailable = is_false(obs_obj.and_then(|m| m.get("bridgeAvailable")));
    let failed_launch = truthy(obs_obj.and_then(|m| m.get("failedLaunch")));
    let blocked = bridge_unavailable || failed_launch || !undeclared_actions.is_empty();

    let reached_meaningful_state = is_true(obs_obj.and_then(|m| m.get("reachedMeaningfulState")));
    let shallow = !reached_meaningful_state;
    let ready = is_true(obs_obj.and_then(|m| m.get("ready")));
    let status = if blocked {
        "blocked"
    } else if !ready || shallow {
        "unproven"
    } else {
        "pass"
    };

    let mut coverage_gaps: Vec<Value> = Vec::new();
    if bridge_unavailable {
        coverage_gaps.push(json!("native-bridge-unavailable"));
    }
    if shallow {
        coverage_gaps.push(json!("shallow-traversal"));
    }

    json!({
        "schemaVersion": 1,
        "kind": "legion-runtime-receipt",
        "provider": "runtime.native-surface",
        "surfaceId": spec_obj.and_then(|m| m.get("surfaceId")).cloned().unwrap_or(Value::Null),
        "state": obs_obj.and_then(|m| m.get("state")).cloned().unwrap_or(json!("default")),
        "status": status,
        "complete": status == "pass",
        "shallow": shallow,
        "undeclaredActions": undeclared_actions,
        "processLifecycle": obs_obj.and_then(|m| m.get("processLifecycle")).cloned().unwrap_or(Value::Null),
        "resourceUse": obs_obj.and_then(|m| m.get("resourceUse")).cloned().unwrap_or(Value::Null),
        "recovery": obs_obj.and_then(|m| m.get("recovery")).cloned().unwrap_or(Value::Null),
        "coverageGaps": coverage_gaps,
        "binding": spec_obj.and_then(|m| m.get("binding")).cloned().unwrap_or(json!({})),
    })
}

/* =======================================================================
 * browser/index.mjs
 * ===================================================================== */

#[derive(Default, Clone, Debug)]
pub struct RuntimeReceiptInput {
    pub surfaces_found: Option<i64>,
    pub surfaces_tested: Option<i64>,
    pub console_errors: Option<i64>,
    pub long_tasks: Option<i64>,
    pub screenshots: Option<Vec<Value>>,
    pub shallow: Option<bool>,
}

/// Faithful port of `runtimeReceipt(...)`.
pub fn runtime_receipt(input: RuntimeReceiptInput) -> Value {
    let surfaces_found = input.surfaces_found.unwrap_or(0);
    let surfaces_tested = input.surfaces_tested.unwrap_or(0);
    let console_errors = input.console_errors.unwrap_or(0);
    let long_tasks = input.long_tasks.unwrap_or(0);
    let screenshots = input.screenshots.unwrap_or_default();
    let shallow = input.shallow.unwrap_or(false);
    let complete = surfaces_tested == surfaces_found && surfaces_found > 0;

    json!({
        "schemaVersion": 1,
        "kind": "legion-browser-runtime",
        "surfacesFound": surfaces_found,
        "surfacesTested": surfaces_tested,
        "consoleErrors": console_errors,
        "longTasks": long_tasks,
        "screenshots": screenshots,
        "complete": complete,
        "shallowTraversal": shallow,
        "coverageGaps": if shallow { vec![json!({"kind": "runtime-shallow-traversal"})] } else { vec![] },
    })
}

#[derive(Default, Clone, Debug)]
pub struct ConsoleErrorObservationInput {
    pub file: Option<String>,
    pub message: Option<String>,
    pub surface: Option<String>,
}

/// Faithful port of `consoleErrorObservation(...)`.
pub fn console_error_observation(input: ConsoleErrorObservationInput) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-console-error",
        "file": input.file,
        "message": input.message,
        "surface": input.surface,
    })
}

#[derive(Clone, Debug)]
pub struct PerformanceObservationInput {
    pub surface: Value,
    pub long_tasks: f64,
    pub interaction_latency_ms: f64,
    pub threshold_ms: Option<f64>,
}

/// Faithful port of `performanceObservation(...)`.
pub fn performance_observation(input: PerformanceObservationInput) -> Value {
    let threshold_ms = input.threshold_ms.unwrap_or(200.0);
    let violated = input.long_tasks > 0.0 || input.interaction_latency_ms > threshold_ms;
    json!({
        "schemaVersion": 1,
        "kind": "legion-performance-observation",
        "surface": input.surface,
        "longTasks": input.long_tasks,
        "interactionLatencyMs": input.interaction_latency_ms,
        "thresholdMs": threshold_ms,
        "violated": violated,
    })
}

/* =======================================================================
 * service/api/index.mjs, service/data/index.mjs
 * ===================================================================== */

/// Faithful port of `verifyServiceApi`'s wrapping behaviour. The JS module
/// computes `verifyApiExercise(input)` (owned by `web/api/index.mjs`,
/// outside this port's file set) and relabels it; this function takes that
/// already-computed exercise receipt.
pub fn verify_service_api(exercise_receipt: Value) -> Value {
    let mut map = match exercise_receipt {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    map.remove("digest");
    map.remove("kind");
    map.remove("schemaVersion");
    let mut receipt = Map::new();
    receipt.insert("provider".to_string(), json!("runtime.service.api"));
    for (k, v) in map {
        receipt.insert(k, v);
    }
    finalize("legion-service-api-provider", Value::Object(receipt))
}

/// Faithful port of `verifyServiceData`'s wrapping behaviour. See
/// [`verify_service_api`] for the same caveat regarding `verifyDataExercise`
/// (owned by `web/data/index.mjs`, outside this port's file set).
pub fn verify_service_data(exercise_receipt: Value) -> Value {
    let mut map = match exercise_receipt {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    map.remove("digest");
    map.remove("kind");
    map.remove("schemaVersion");
    let mut receipt = Map::new();
    receipt.insert("provider".to_string(), json!("runtime.service.data"));
    receipt.insert("claimLevel".to_string(), json!("runtime"));
    for (k, v) in map {
        receipt.insert(k, v);
    }
    finalize("legion-service-data-provider", Value::Object(receipt))
}

/* =======================================================================
 * runtime/worker/index.mjs (the one constant `service/core` and
 * `service/faults` both depend on)
 * ===================================================================== */

pub const SERVICE_RUNTIME_SCENARIOS: [&str; 17] = [
    "api-contract",
    "identity-authorization",
    "data-effect",
    "timeout-retry",
    "idempotency",
    "rate-cost-limit",
    "queue-ordering",
    "queue-duplicate",
    "poison-message",
    "backpressure",
    "worker-restart",
    "graceful-shutdown",
    "health-readiness",
    "migration",
    "capacity",
    "fault-recovery",
    "observability",
];

/* =======================================================================
 * service/core/index.mjs
 * ===================================================================== */

/// Port of the JS `adapter` argument: `{ execute({ id, binding }) }`.
/// The JS wrapper `try`/`catch`es a throwing `adapter.execute` and turns it
/// into `{ status: 'error', terminal: true }`; Rust async trait
/// implementations are expected not to panic, so that catch is not modeled.
/// A `None` return corresponds to `adapter.execute` being absent
/// (`typeof adapter.execute === 'function'` false) or resolving to `null`.
#[async_trait]
pub trait ServiceRuntimeAdapter: Send + Sync {
    async fn execute(&self, scenario_id: &str, binding: &Value) -> Option<Value>;
}

#[derive(Default, Clone, Debug)]
pub struct ServiceRuntimeTarget {
    pub id: Option<String>,
    pub artifact_digest: Option<String>,
    pub environment: Option<String>,
    pub configuration_digest: Option<String>,
    pub deployment: Option<String>,
    pub region: Option<String>,
    pub datastore: Option<String>,
    pub queue: Option<String>,
    pub external_providers: Vec<Value>,
    pub workload: Option<Value>,
}

/// Faithful port of `assessServiceRuntime({ target, adapter, productionControls })`.
pub async fn assess_service_runtime(
    target: &ServiceRuntimeTarget,
    adapter: &dyn ServiceRuntimeAdapter,
    production_controls: &[String],
) -> Value {
    let binding = json!({
        "targetId": target.id,
        "artifactDigest": target.artifact_digest,
        "environment": target.environment,
        "configurationDigest": target.configuration_digest,
        "deployment": target.deployment,
        "region": target.region,
        "datastore": target.datastore,
        "queue": target.queue,
        "externalProviders": target.external_providers,
        "workload": target.workload,
    });

    let mut receipts: Vec<Value> = Vec::new();
    for id in SERVICE_RUNTIME_SCENARIOS {
        let result = adapter.execute(id, &binding).await;
        let status_str = result
            .as_ref()
            .and_then(|r| r.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let status_ok = matches!(status_str.as_str(), "pass" | "fail" | "partial" | "unproven" | "blocked" | "error");
        let terminal_ok = result.as_ref().and_then(|r| r.get("terminal")) == Some(&Value::Bool(true));
        let valid = result.is_some() && status_ok && terminal_ok;

        let restartable = result
            .as_ref()
            .and_then(|r| r.get("restartable"))
            .map(|v| v == &Value::Bool(true))
            .unwrap_or(false);
        let restart_gap = id == "worker-restart" && valid && status_str == "pass" && !restartable;

        let final_status = if restart_gap {
            "partial".to_string()
        } else if valid {
            status_str
        } else {
            "unproven".to_string()
        };

        let coverage_gaps: Vec<Value> = if valid {
            if restart_gap {
                vec![json!("worker-restartability-unproven")]
            } else {
                vec![]
            }
        } else {
            vec![json!("runtime-execution-missing")]
        };

        receipts.push(json!({
            "id": id,
            "status": final_status,
            "terminal": true,
            "binding": binding,
            "cleanup": result.as_ref().and_then(|r| r.get("cleanup")).cloned().unwrap_or(Value::Null),
            "evidence": result.as_ref().and_then(|r| r.get("evidence")).cloned().unwrap_or(Value::Null),
            "coverageGaps": coverage_gaps,
        }));
    }

    let external_gaps: Vec<String> = production_controls
        .iter()
        .map(|id| format!("production-external-evidence-missing:{id}"))
        .collect();

    let failures = receipts
        .iter()
        .filter(|r| matches!(r.get("status").and_then(Value::as_str), Some("fail") | Some("error")))
        .count();
    let missing: Vec<&Value> = receipts
        .iter()
        .filter(|r| !matches!(r.get("status").and_then(Value::as_str), Some("pass") | Some("fail")))
        .collect();

    let status = if failures > 0 {
        "fail"
    } else if !missing.is_empty() || !external_gaps.is_empty() {
        "partial"
    } else {
        "pass"
    };
    let claims_runtime = if failures > 0 {
        "failed"
    } else if !missing.is_empty() {
        "partial"
    } else {
        "evidenced"
    };

    let mut all_gaps: Vec<String> = external_gaps;
    for item in &missing {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("");
        all_gaps.push(format!("{id}:runtime-execution-missing"));
    }
    all_gaps.sort();

    json!({
        "schemaVersion": 1,
        "kind": "legion-service-worker-runtime-evidence",
        "status": status,
        "terminal": true,
        "binding": binding,
        "receipts": receipts,
        "claims": { "runtime": claims_runtime, "source": "unaffected" },
        "coverageGaps": all_gaps,
    })
}

/* =======================================================================
 * service/faults/index.mjs
 * ===================================================================== */

fn fixture_status(fixture: &str) -> &'static str {
    match fixture {
        "clean" => "pass",
        "defect" => "fail",
        "partial" => "partial",
        "stale-environment" => "unproven",
        "unsupported-runtime" => "blocked",
        _ => "blocked",
    }
}

/// Faithful port of `createServiceFixtureAdapter(fixture, { onExecute })`.
pub struct ServiceFixtureAdapter {
    fixture: String,
    on_execute: Option<Box<dyn Fn(&str, &Value) + Send + Sync>>,
}

impl ServiceFixtureAdapter {
    pub fn new(fixture: impl Into<String>) -> Self {
        Self {
            fixture: fixture.into(),
            on_execute: None,
        }
    }

    pub fn with_on_execute(mut self, callback: impl Fn(&str, &Value) + Send + Sync + 'static) -> Self {
        self.on_execute = Some(Box::new(callback));
        self
    }
}

#[async_trait]
impl ServiceRuntimeAdapter for ServiceFixtureAdapter {
    async fn execute(&self, scenario_id: &str, binding: &Value) -> Option<Value> {
        if !SERVICE_RUNTIME_SCENARIOS.contains(&scenario_id) {
            return Some(json!({
                "status": "error",
                "terminal": true,
                "coverageGaps": ["unsupported-runtime-scenario"],
            }));
        }
        if let Some(callback) = &self.on_execute {
            callback(scenario_id, binding);
        }
        let restartable = scenario_id == "worker-restart";
        let status = fixture_status(&self.fixture);
        Some(json!({
            "status": status,
            "terminal": true,
            "restartable": restartable,
            "evidence": {
                "fixture": self.fixture,
                "scenario": scenario_id,
                "binding": binding,
                "restartable": restartable,
            },
            "cleanup": {
                "status": "pass",
                "deployment": binding.get("deployment").cloned().unwrap_or(Value::Null),
                "region": binding.get("region").cloned().unwrap_or(Value::Null),
                "datastore": binding.get("datastore").cloned().unwrap_or(Value::Null),
            },
        }))
    }
}

/// Faithful port of `createServiceFixtureAdapter`.
pub fn create_service_fixture_adapter(fixture: &str) -> ServiceFixtureAdapter {
    ServiceFixtureAdapter::new(fixture)
}

/// Faithful port of `export const createFaultAdapter = createServiceFixtureAdapter;`.
pub fn create_fault_adapter(fixture: &str) -> ServiceFixtureAdapter {
    create_service_fixture_adapter(fixture)
}
