//! Port of `src/providers/runtime/web/protocols/index.mjs`
//! (`executeWebProtocol`) — chunk wf050.
//!
//! Two collaborators sit outside this chunk's owned paths:
//! `sanitizeProducedArtifact` (`src/lib/platform/artifact-sanitize.mjs`)
//! and the protocol plan table `WEB_PROTOCOLS` (`../journey-plan.mjs`,
//! itself loaded from `registry/platform-scenarios/web.json`). Both are
//! taken as parameters here (`sanitize_artifact`, `plan`) rather than
//! reimplemented, so this port stays exact for the logic this chunk owns
//! without duplicating registries or sanitizers owned elsewhere. See the
//! wf050 report for this dependency.

use serde_json::{json, Value};

use super::shared::{exact_binding, finalize, redact};

/// One row of the `WEB_PROTOCOLS` plan table this function reads:
/// `protocolId`, `applicable`.
pub struct ProtocolPlanRow<'a> {
    pub protocol_id: &'a str,
    pub applicable: bool,
}

/// Result of the (owned-elsewhere) `sanitizeProducedArtifact(artifact)`
/// call, plus the `bound` flag `executeWebProtocol` computes itself.
pub struct SanitizedArtifact {
    pub valid: bool,
    pub sensitive: bool,
    pub bound: bool,
    pub artifact: Value,
}

/// Result of the (injected) `adapter.execute({ binding, protocol })` call.
pub enum AdapterExecuteResult {
    Ok(Value),
    Err { name: String, message: String },
}

/// Port of `executeWebProtocol({ binding, protocol, adapter })`.
///
/// `adapter_execute` stands in for `typeof adapter.execute === 'function'`
/// plus the call itself: `None` means no `execute` function was supplied;
/// `Some(f)` is invoked and its result (or thrown error) handled exactly as
/// the JS `try { ... } catch (error) { ... }` block does.
pub fn execute_web_protocol(
    input: &Value,
    plan: &[ProtocolPlanRow],
    sanitize_artifact: &dyn Fn(&Value) -> (bool, bool, Value),
    adapter_execute: Option<&dyn Fn(&Value, &str) -> AdapterExecuteResult>,
) -> Value {
    let binding = input.get("binding").cloned().unwrap_or(json!({}));
    let protocol = input.get("protocol").cloned().unwrap_or(Value::Null);
    let protocol_str = protocol.as_str();

    let mut gaps = exact_binding(&binding).gaps.into_iter().map(|k| format!("binding-missing:{k}")).collect::<Vec<_>>();
    if protocol_str.is_none() {
        gaps.push("protocol-missing".to_string());
    }

    if binding.get("environment").and_then(Value::as_str) == Some("production") {
        return finalize(
            "legion-web-protocol-receipt",
            json!({
                "status": "blocked",
                "terminal": true,
                "binding": binding,
                "protocol": protocol,
                "observedState": Value::Null,
                "durableState": Value::Null,
                "artifacts": [],
                "coverageGaps": ["production-effect-forbidden"],
            }),
        );
    }

    let plan_row = protocol_str.and_then(|p| plan.iter().find(|row| row.protocol_id == p));
    let plan_row = match plan_row {
        None => {
            let mut g = gaps.clone();
            g.push("protocol-unrecognized".to_string());
            g.sort();
            return finalize(
                "legion-web-protocol-receipt",
                json!({
                    "status": "unproven",
                    "terminal": true,
                    "binding": binding,
                    "protocol": protocol,
                    "observedState": Value::Null,
                    "durableState": Value::Null,
                    "artifacts": [],
                    "coverageGaps": g,
                }),
            );
        }
        Some(row) => row,
    };

    if !plan_row.applicable {
        let mut g = gaps.clone();
        g.push("protocol-not-applicable".to_string());
        g.sort();
        return finalize(
            "legion-web-protocol-receipt",
            json!({
                "status": "unsupported",
                "terminal": true,
                "binding": binding,
                "protocol": protocol,
                "observedState": Value::Null,
                "durableState": Value::Null,
                "artifacts": [],
                "coverageGaps": g,
            }),
        );
    }

    if !gaps.is_empty() {
        gaps.sort();
        return finalize(
            "legion-web-protocol-receipt",
            json!({
                "status": "unproven",
                "terminal": true,
                "binding": binding,
                "protocol": protocol,
                "observedState": Value::Null,
                "durableState": Value::Null,
                "artifacts": [],
                "coverageGaps": gaps,
            }),
        );
    }

    let adapter_execute = match adapter_execute {
        None => {
            let mut g = gaps.clone();
            g.push("protocol-adapter-missing".to_string());
            g.sort();
            return finalize(
                "legion-web-protocol-receipt",
                json!({
                    "status": "unproven",
                    "terminal": true,
                    "binding": binding,
                    "protocol": protocol,
                    "observedState": Value::Null,
                    "durableState": Value::Null,
                    "artifacts": [],
                    "coverageGaps": g,
                }),
            );
        }
        Some(f) => f,
    };

    match adapter_execute(&binding, protocol_str.unwrap()) {
        AdapterExecuteResult::Err { name, message } => finalize(
            "legion-web-protocol-receipt",
            json!({
                "status": "error",
                "terminal": true,
                "binding": binding,
                "protocol": protocol,
                "observedState": Value::Null,
                "durableState": Value::Null,
                "artifacts": [],
                "errors": [{ "name": name, "message": redact(&Value::String(message)) }],
                "coverageGaps": ["protocol-exercise-error"],
            }),
        ),
        AdapterExecuteResult::Ok(raw_observed) => {
            let raw_artifacts = raw_observed.get("artifacts").cloned();
            // Each entry: (valid && bound, sensitive, sanitized artifact value).
            let (processed_bound, artifacts_shape_invalid): (Vec<(bool, bool, Value)>, bool) = match &raw_artifacts {
                None => (Vec::new(), false),
                Some(Value::Array(items)) => {
                    let processed = items
                        .iter()
                        .map(|artifact| {
                            let (valid, sensitive, sanitized) = sanitize_artifact(artifact);
                            let bound = binding
                                .as_object()
                                .map(|bmap| {
                                    bmap.iter().all(|(k, v)| artifact.get("binding").and_then(|b| b.get(k)) == Some(v))
                                })
                                .unwrap_or(true);
                            (valid && bound, sensitive, sanitized)
                        })
                        .collect::<Vec<_>>();
                    (processed, false)
                }
                Some(_) => (Vec::new(), true),
            };

            let mut gaps: Vec<String> = Vec::new();
            let any_invalid_or_unbound = artifacts_shape_invalid
                || processed_bound.iter().any(|(valid_and_bound, _, _)| !*valid_and_bound);
            if any_invalid_or_unbound {
                gaps.push("protocol-artifact-invalid".to_string());
            }
            if processed_bound.iter().any(|(_, sensitive, _)| *sensitive) {
                gaps.push("protocol-artifact-sensitive".to_string());
            }

            let mut observed_input = raw_observed.clone();
            if let Value::Object(map) = &mut observed_input {
                map.remove("artifacts");
            }
            let observed = redact(&observed_input);

            let observed_state = observed.get("observedState").cloned();
            if observed_state.is_none() || observed_state == Some(Value::Null) {
                gaps.push("observed-state-missing".to_string());
            }
            let durable_state = observed.get("durableState").cloned();
            if durable_state.is_none() || durable_state == Some(Value::Null) {
                gaps.push("durable-state-missing".to_string());
            }

            let status = observed.get("status").and_then(Value::as_str).unwrap_or("pass").to_string();
            if !["pass", "fail", "partial", "unproven", "blocked", "error"].contains(&status.as_str()) {
                gaps.push(format!("protocol-status-{status}"));
            }

            let final_status = if !gaps.is_empty() { "unproven".to_string() } else { status.clone() };
            let final_artifacts: Vec<Value> = processed_bound
                .into_iter()
                .filter(|(valid_and_bound, _, _)| *valid_and_bound)
                .map(|(_, _, artifact)| artifact)
                .collect();

            gaps.sort();
            finalize(
                "legion-web-protocol-receipt",
                json!({
                    "status": final_status,
                    "terminal": true,
                    "binding": binding,
                    "protocol": protocol,
                    "observedState": observed_state.unwrap_or(Value::Null),
                    "durableState": durable_state.unwrap_or(Value::Null),
                    "artifacts": final_artifacts,
                    "coverageGaps": gaps,
                }),
            )
        }
    }
}
