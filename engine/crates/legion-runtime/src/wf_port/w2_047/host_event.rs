//! Faithful port of `src/lib/host/arcane/host-event.mjs` — `normalizeHostEvent`
//! and `classifyObservation` only (see `wf_port::w2_047` module docs for the
//! full scope note).

use serde_json::{json, Value as Json};

/// Mirrors JS `EVENT_TYPE`.
pub const EVENT_TYPE: &[&str] = &[
    "session-start",
    "subagent-start",
    "user-prompt-submit",
    "post-compact",
    "pre-effect",
    "post-effect",
    "post-effect-failure",
    "stop",
    "ci-boundary",
];

/// Mirrors JS `LEGACY_HOST_EVENT_TYPE`.
pub fn legacy_host_event_type(name: &str) -> Option<&'static str> {
    Some(match name {
        "SessionStart" => "session-start",
        "SubagentStart" => "subagent-start",
        "UserPromptSubmit" => "user-prompt-submit",
        "PostCompact" => "post-compact",
        "PreToolUse" => "pre-effect",
        "PostToolUse" => "post-effect",
        "PostToolUseFailure" => "post-effect-failure",
        "Stop" => "stop",
        _ => return None,
    })
}

/// Mirrors JS `LIFECYCLE_TELEMETRY_EVENT_TYPES`.
pub const LIFECYCLE_TELEMETRY_EVENT_TYPES: &[&str] = &[
    "session-start",
    "user-prompt-submit",
    "stop",
    "ci-boundary",
    "subagent-start",
    "post-compact",
];

/// Mirrors JS `EFFECT_OBSERVATION_CLASS`.
pub const EFFECT_OBSERVATION_CLASS: &[&str] = &[
    "mutation-observation",
    "deterministic-check-candidate",
    "source-observation",
    "failure",
    "non-qualifying-telemetry",
];

const FILE_MUTATION_CLASSES: &[&str] = &["FILE_WRITE", "FILE_DELETE", "FILE_MOVE"];

// Mirrors JS `OTHER_MUTATING_CLASSES` — every other EFFECT_CLASS value that
// is a mutation once it succeeds. COMMAND_EXEC is deliberately excluded: a
// carrier, not a mutation in itself.
const OTHER_MUTATING_CLASSES: &[&str] = &[
    "NETWORK_EGRESS",
    "PROCESS_SPAWN",
    "CREDENTIAL_ACCESS",
    "DEPENDENCY_INSTALL",
    "VCS_COMMIT",
    "VCS_PUSH",
    "PUBLISH",
    "EXTERNAL_SIDE_EFFECT",
];

/// Error raised when a normalized candidate fails `HOST_EVENT_SCHEMA`
/// structural validation. Mirrors `ArcaneError('ARC_HOST_EVENT_INVALID', ...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEventInvalid {
    pub issues: Vec<String>,
}

impl std::fmt::Display for HostEventInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ARC_HOST_EVENT_INVALID: normalized host event does not satisfy HOST_EVENT_SCHEMA ({:?})", self.issues)
    }
}
impl std::error::Error for HostEventInvalid {}

fn is_ulid_like(s: &str, prefix: &str) -> bool {
    // Crockford base32, 26 chars, after the given prefix — mirrors the JS
    // regex character classes without pulling in a regex dependency for a
    // single fixed-width check.
    let Some(rest) = s.strip_prefix(prefix) else { return false };
    rest.len() == 26
        && rest.chars().all(|c| {
            c.is_ascii_digit()
                || matches!(
                    c.to_ascii_uppercase(),
                    'A'..='H' | 'J' | 'K' | 'M' | 'N' | 'P'..='T' | 'V'..='Z'
                )
        })
}

/// Structural validation of the fields `normalize_host_event` fills, mirroring
/// the subset of `HOST_EVENT_SCHEMA` that a freshly-normalized candidate can
/// actually violate (an unknown `eventType`, or a caller-supplied `eventId`/
/// `runId`/`requestId`/`contractId` that does not match its pattern). Full
/// `additionalProperties:false` closed-schema enforcement over arbitrary
/// caller JSON is out of this port's budget (no schema-validator dependency);
/// this reproduces the acceptance-relevant checks.
fn validate_candidate(c: &Json) -> Vec<String> {
    let mut issues = Vec::new();
    let event_type = c.get("eventType").and_then(Json::as_str);
    match event_type {
        Some(t) if EVENT_TYPE.contains(&t) => {}
        _ => issues.push("eventType".to_string()),
    }
    if let Some(id) = c.get("eventId").and_then(Json::as_str) {
        if !is_ulid_like(id, "hev_") {
            issues.push("eventId".to_string());
        }
    } else {
        issues.push("eventId".to_string());
    }
    if let Some(rid) = c.get("runId").and_then(Json::as_str) {
        if !is_ulid_like(rid, "run_") {
            issues.push("runId".to_string());
        }
    }
    if let Some(rid) = c.get("requestId").and_then(Json::as_str) {
        if !is_ulid_like(rid, "req_") {
            issues.push("requestId".to_string());
        }
    }
    if let Some(cid) = c.get("contractId").and_then(Json::as_str) {
        let ok = cid.strip_prefix("EC-").map(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())).unwrap_or(false);
        if !ok {
            issues.push("contractId".to_string());
        }
    }
    if !c.get("workspace").and_then(Json::as_str).map(|s| !s.is_empty()).unwrap_or(false) {
        issues.push("workspace".to_string());
    }
    issues
}

/// Normalize a raw, adapter-native event into the canonical host-event shape.
/// `event_id_gen` supplies a fresh `hev_<ulid>` id when `raw.eventId` is
/// absent (JS: ``eventId ?? `hev_${ulid()}` ``) — injected rather than a hard
/// `ulid` dependency, since this chunk owns no id-generation module.
/// `now_iso` supplies the current instant in the same case
/// (`raw.time ?? new Date().toISOString()`).
///
/// Mirrors `normalizeHostEvent(raw, { adapter })` field-for-field.
pub fn normalize_host_event(
    raw: &Json,
    adapter: Option<&Json>,
    event_id_gen: impl FnOnce() -> String,
    now_iso: impl FnOnce() -> String,
) -> Result<Json, HostEventInvalid> {
    let get = |k: &str| raw.get(k).cloned();
    let raw_event_type = raw.get("eventType").and_then(Json::as_str);
    let event_type = raw_event_type
        .and_then(legacy_host_event_type)
        .or(raw_event_type)
        .map(Json::from)
        .unwrap_or(Json::Null);

    let event_id = get("eventId").filter(|v| !v.is_null()).unwrap_or_else(|| Json::from(event_id_gen()));
    let time = get("time").filter(|v| !v.is_null()).unwrap_or_else(|| Json::from(now_iso()));

    let mut candidate = json!({
        "schemaVersion": 1,
        "kind": "arcane-host-event",
        "eventId": event_id,
        "eventType": event_type,
        "time": time,

        "adapter": get("adapter").filter(|v| !v.is_null()).or_else(|| adapter.cloned()).unwrap_or(Json::Null),
        "client": get("client").unwrap_or(Json::Null),
        "host": get("host").unwrap_or(Json::Null),

        "runId": get("runId").unwrap_or(Json::Null),
        "taskId": get("taskId").unwrap_or(Json::Null),
        "sessionId": get("sessionId").unwrap_or(Json::Null),
        "requestId": get("requestId").unwrap_or(Json::Null),
        "contractId": get("contractId").unwrap_or(Json::Null),

        "workspace": get("workspace").filter(|v| !v.is_null()).unwrap_or_else(|| Json::from("")),
        "subject": get("subject").unwrap_or(Json::Null),

        "actor": get("actor").filter(|v| !v.is_null()).unwrap_or_else(|| json!({"issuerId": "unknown", "processIdentity": null})),
        "operation": get("operation").filter(|v| !v.is_null()).unwrap_or_else(|| json!({"toolId": "unknown", "operationId": "unknown", "argumentDigest": null})),
        "sourceRevision": get("sourceRevision").unwrap_or(Json::Null),

        "effect": get("effect").unwrap_or(Json::Null),
        "result": get("result").unwrap_or(Json::Null),

        "pathMeta": get("pathMeta").unwrap_or(Json::Null),
        "processMeta": get("processMeta").unwrap_or(Json::Null),
        "networkMeta": get("networkMeta").unwrap_or(Json::Null),

        "priorCorrelation": get("priorCorrelation").unwrap_or(Json::Null),
        "checkCorrelation": get("checkCorrelation").unwrap_or(Json::Null),
        "hostEnforcement": get("hostEnforcement").filter(|v| !v.is_null()).unwrap_or_else(|| json!({"capabilities": [], "knownBypasses": []})),

        "replayNonce": get("replayNonce").unwrap_or(Json::Null),
        "replaySequence": get("replaySequence").unwrap_or(Json::Null),
        "idempotencyKey": get("idempotencyKey").unwrap_or(Json::Null),
    });

    if let Some(ext) = raw.get("extensions") {
        candidate["extensions"] = ext.clone();
    }

    let issues = validate_candidate(&candidate);
    if !issues.is_empty() {
        return Err(HostEventInvalid { issues });
    }
    Ok(candidate)
}

/// Classify a completed observation. Mirrors `classifyObservation(event,
/// {policy})`'s rules table exactly, including its ordering (failure first,
/// then FILE_* mutation, then other mutating classes, then COMMAND_EXEC, then
/// the no-effect-class branch, then the unrecognized-by-policy branch).
///
/// `effect_rule` mirrors `policy.effectRule(effectClass)` — `None` mirrors
/// "no policy supplied" (JS: `policy && typeof policy.effectRule ===
/// 'function'`), so that branch is skipped exactly as in JS when no rule
/// function is given.
pub fn classify_observation(event: &Json, effect_rule: Option<&dyn Fn(&str) -> bool>) -> &'static str {
    let outcome = event.get("result").and_then(|r| r.get("outcome")).and_then(Json::as_str);
    let exit_code = event.get("result").and_then(|r| r.get("exitCode")).and_then(Json::as_i64);
    let effect_class = event.get("effect").and_then(|e| e.get("effectClass")).and_then(Json::as_str);

    if outcome == Some("failure") || outcome == Some("blocked") || matches!(exit_code, Some(c) if c != 0) {
        return "failure";
    }

    if let Some(ec) = effect_class {
        if FILE_MUTATION_CLASSES.contains(&ec) {
            return "mutation-observation";
        }
        if OTHER_MUTATING_CLASSES.contains(&ec) {
            return "mutation-observation";
        }
        if ec == "COMMAND_EXEC" {
            let has_check = event
                .get("checkCorrelation")
                .and_then(|c| c.get("declaredCheckId"))
                .and_then(Json::as_str)
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            return if has_check { "deterministic-check-candidate" } else { "source-observation" };
        }
    } else {
        let event_type = event.get("eventType").and_then(Json::as_str).unwrap_or("");
        return if LIFECYCLE_TELEMETRY_EVENT_TYPES.contains(&event_type) {
            "non-qualifying-telemetry"
        } else {
            "source-observation"
        };
    }

    // effectClass is Some but not in FILE_MUTATION_CLASSES/OTHER_MUTATING_CLASSES/COMMAND_EXEC
    // (unreachable against the frozen 12-value EFFECT_CLASS enum, matching the JS comment).
    if let Some(rule) = effect_rule {
        if !rule(effect_class.unwrap_or("")) {
            return "non-qualifying-telemetry";
        }
    }
    "source-observation"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_raw() -> Json {
        json!({
            "eventType": "PreToolUse",
            "workspace": "/repo",
        })
    }

    #[test]
    fn normalizes_legacy_event_type() {
        let out = normalize_host_event(&ok_raw(), None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap();
        assert_eq!(out["eventType"], "pre-effect");
        assert_eq!(out["kind"], "arcane-host-event");
        assert_eq!(out["schemaVersion"], 1);
        assert_eq!(out["hostEnforcement"], json!({"capabilities": [], "knownBypasses": []}));
    }

    #[test]
    fn passes_through_already_canonical_event_type() {
        let raw = json!({"eventType": "pre-effect", "workspace": "/repo"});
        let out = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "x".to_string()).unwrap();
        assert_eq!(out["eventType"], "pre-effect");
    }

    #[test]
    fn rejects_unknown_event_type() {
        let raw = json!({"eventType": "NotARealEvent", "workspace": "/repo"});
        let err = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "x".to_string()).unwrap_err();
        assert!(err.issues.contains(&"eventType".to_string()));
    }

    #[test]
    fn rejects_empty_workspace() {
        let raw = json!({"eventType": "pre-effect", "workspace": ""});
        let err = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "x".to_string()).unwrap_err();
        assert!(err.issues.contains(&"workspace".to_string()));
    }

    #[test]
    fn extensions_carried_only_when_present() {
        let raw = json!({"eventType": "Stop", "workspace": "/repo"});
        let out = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "x".to_string()).unwrap();
        assert!(out.get("extensions").is_none());

        let raw2 = json!({"eventType": "Stop", "workspace": "/repo", "extensions": {"a": 1}});
        let out2 = normalize_host_event(&raw2, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "x".to_string()).unwrap();
        assert_eq!(out2["extensions"], json!({"a": 1}));
    }

    #[test]
    fn classify_failure_outcome_first() {
        let event = json!({"result": {"outcome": "failure"}, "effect": {"effectClass": "FILE_WRITE"}});
        assert_eq!(classify_observation(&event, None), "failure");
    }

    #[test]
    fn classify_nonzero_exit_is_failure() {
        let event = json!({"result": {"outcome": "success", "exitCode": 2}});
        assert_eq!(classify_observation(&event, None), "failure");
    }

    #[test]
    fn classify_file_write_is_mutation() {
        let event = json!({"result": {"outcome": "success", "exitCode": 0}, "effect": {"effectClass": "FILE_WRITE"}});
        assert_eq!(classify_observation(&event, None), "mutation-observation");
    }

    #[test]
    fn classify_other_mutating_classes() {
        for ec in ["NETWORK_EGRESS", "PROCESS_SPAWN", "CREDENTIAL_ACCESS", "DEPENDENCY_INSTALL", "VCS_COMMIT", "VCS_PUSH", "PUBLISH", "EXTERNAL_SIDE_EFFECT"] {
            let event = json!({"result": {"outcome": "success"}, "effect": {"effectClass": ec}});
            assert_eq!(classify_observation(&event, None), "mutation-observation", "class {ec}");
        }
    }

    #[test]
    fn classify_command_exec_without_check_is_source_observation() {
        let event = json!({"result": {"outcome": "success"}, "effect": {"effectClass": "COMMAND_EXEC"}});
        assert_eq!(classify_observation(&event, None), "source-observation");
    }

    #[test]
    fn classify_command_exec_with_declared_check_is_check_candidate() {
        let event = json!({
            "result": {"outcome": "success"},
            "effect": {"effectClass": "COMMAND_EXEC"},
            "checkCorrelation": {"declaredCheckId": "chk_1", "method": "manual"},
        });
        assert_eq!(classify_observation(&event, None), "deterministic-check-candidate");
    }

    #[test]
    fn classify_no_effect_class_lifecycle_is_non_qualifying() {
        let event = json!({"result": null, "eventType": "session-start"});
        assert_eq!(classify_observation(&event, None), "non-qualifying-telemetry");
    }

    #[test]
    fn classify_no_effect_class_non_lifecycle_is_source_observation() {
        let event = json!({"result": null, "eventType": "pre-effect"});
        assert_eq!(classify_observation(&event, None), "source-observation");
    }
}
