//! Faithful port of `src/lib/host/arcane/host-event.mjs` — `EVENT_TYPE`,
//! `LEGACY_HOST_EVENT_TYPE`, `LIFECYCLE_TELEMETRY_EVENT_TYPES`,
//! `HOST_EVENT_SCHEMA`, `HOST_EVENT_BOUND_FIELDS`, `validateHostEvent`,
//! `normalizeHostEvent`, and `classifyObservation` (see `wf_port::w2_047`
//! module docs for the crate-level scope note).
//!
//! `validate_host_event` reproduces the full closed `HOST_EVENT_SCHEMA`
//! (`additionalProperties: false` at every object level, exactly one open
//! bag — `extensions`) using the same generic JSON-Schema-subset engine
//! `legion-policy`'s `wf068` chunk already ports from
//! `qualification/schema-validator.mjs`
//! (`legion_policy::wf_port::wf068::validate_schema`), which this crate
//! already depends on (`legion-runtime` -> `legion-policy` in Cargo.toml).
//! `normalize_host_event` now runs the same full-schema check on its
//! candidate (previously an ad-hoc subset of field checks), matching JS
//! `normalizeHostEvent`'s call to `validateHostEvent` exactly.

use legion_policy::wf_port::wf068::validate_schema;
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

/// Mirrors JS `DIGEST_PATTERN` (`contracts/arcane/canonical.mjs`).
const DIGEST_RE: &str = r"^sha256:[0-9a-f]{64}$";
/// Mirrors JS `DATE_TIME_RE` (`host-event.mjs`).
const DATE_TIME_RE: &str = r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$";

/// Mirrors JS `EFFECT_CLASS` (`packages/contracts/enums.mjs`) — the frozen
/// 12-value enum `EFFECT_IDENTITY_SCHEMA.properties.effectClass` checks
/// against.
const EFFECT_CLASS: &[&str] = &[
    "FILE_WRITE",
    "FILE_DELETE",
    "FILE_MOVE",
    "COMMAND_EXEC",
    "NETWORK_EGRESS",
    "PROCESS_SPAWN",
    "CREDENTIAL_ACCESS",
    "DEPENDENCY_INSTALL",
    "VCS_COMMIT",
    "VCS_PUSH",
    "PUBLISH",
    "EXTERNAL_SIDE_EFFECT",
];

/// Mirrors JS `EFFECT_IDENTITY_SCHEMA`: the proposed effect (pre-effect
/// events) or observed effect (post-effect events) descriptor. Reused
/// (by structural duplication, not `$ref` — same as the JS source, which
/// assigns the same object literal to `effect`, `priorCorrelation.requestedEffect`,
/// and `priorCorrelation.authorizedEffect`) at every site it appears.
fn effect_identity_schema() -> Json {
    json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "required": ["effectClass", "target", "operation"],
        "properties": {
            "effectClass": { "enum": EFFECT_CLASS },
            "target": { "type": "string", "minLength": 1 },
            "operation": { "type": "string", "minLength": 1 },
        },
    })
}

/// Mirrors JS `HOST_EVENT_SCHEMA` field-for-field: the closed host-event
/// schema, `extensions` its one open bag.
fn host_event_schema() -> Json {
    json!({
        "$id": "arcane-host-event-v1",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schemaVersion", "kind", "eventId", "eventType", "time",
            "adapter", "client", "host",
            "runId", "taskId", "sessionId", "requestId", "contractId",
            "workspace", "subject",
            "actor", "operation", "sourceRevision",
            "effect", "result",
            "pathMeta", "processMeta", "networkMeta",
            "priorCorrelation", "checkCorrelation", "hostEnforcement",
            "replayNonce", "replaySequence", "idempotencyKey",
        ],
        "properties": {
            "schemaVersion": { "const": 1 },
            "kind": { "const": "arcane-host-event" },
            "eventId": { "type": "string", "pattern": r"^hev_[0-9A-HJKMNP-TV-Z]{26}$" },
            "eventType": { "enum": EVENT_TYPE },
            "time": { "type": "string", "pattern": DATE_TIME_RE },

            "adapter": {
                "type": "object", "additionalProperties": false, "required": ["name", "version"],
                "properties": { "name": { "type": "string", "minLength": 1 }, "version": { "type": "string", "minLength": 1 } },
            },
            "client": {
                "type": "object", "additionalProperties": false, "required": ["name", "version"],
                "properties": { "name": { "type": "string", "minLength": 1 }, "version": { "type": "string", "minLength": 1 } },
            },
            "host": {
                "type": "object", "additionalProperties": false, "required": ["platform", "version"],
                "properties": { "platform": { "type": "string", "minLength": 1 }, "version": { "type": "string", "minLength": 1 } },
            },

            "runId": { "type": ["string", "null"], "pattern": r"^run_[0-9A-HJKMNP-TV-Z]{26}$" },
            "taskId": { "type": ["string", "null"], "pattern": r"^T-\d+(\.\d+)*$" },
            "sessionId": { "type": ["string", "null"], "minLength": 1 },
            "requestId": { "type": ["string", "null"], "pattern": r"^req_[0-9A-HJKMNP-TV-Z]{26}$" },
            "contractId": { "type": ["string", "null"], "pattern": r"^EC-\d+$" },

            "workspace": { "type": "string", "minLength": 1 },
            "subject": { "type": ["string", "null"] },

            "actor": {
                "type": "object", "additionalProperties": false, "required": ["issuerId", "processIdentity"],
                "properties": { "issuerId": { "type": "string", "minLength": 1 }, "processIdentity": { "type": ["string", "null"] } },
            },

            "operation": {
                "type": "object", "additionalProperties": false, "required": ["toolId", "operationId", "argumentDigest"],
                "properties": {
                    "toolId": { "type": "string", "minLength": 1 },
                    "operationId": { "type": "string", "minLength": 1 },
                    "argumentDigest": { "type": ["string", "null"], "pattern": DIGEST_RE },
                },
            },

            "sourceRevision": { "type": ["string", "null"], "minLength": 7 },

            "effect": effect_identity_schema(),

            "result": {
                "type": ["object", "null"], "additionalProperties": false, "required": ["outcome", "exitCode", "terminal", "observedDigest"],
                "properties": {
                    "outcome": { "enum": ["success", "failure", "blocked", "no-op"] },
                    "exitCode": { "type": ["integer", "null"] },
                    "terminal": { "type": "boolean" },
                    "observedDigest": { "type": ["string", "null"], "pattern": DIGEST_RE },
                },
            },

            "pathMeta": {
                "type": ["object", "null"], "additionalProperties": false,
                "properties": { "path": { "type": "string" }, "exists": { "type": "boolean" } },
            },
            "processMeta": {
                "type": ["object", "null"], "additionalProperties": false,
                "properties": { "pid": { "type": "integer" }, "parentPid": { "type": ["integer", "null"] }, "executablePath": { "type": ["string", "null"] } },
            },
            "networkMeta": {
                "type": ["object", "null"], "additionalProperties": false,
                "properties": { "host": { "type": "string" }, "port": { "type": ["integer", "null"] }, "protocol": { "type": ["string", "null"] } },
            },

            "priorCorrelation": {
                "type": ["object", "null"], "additionalProperties": false,
                "properties": {
                    "requestId": { "type": ["string", "null"], "pattern": r"^req_[0-9A-HJKMNP-TV-Z]{26}$" },
                    "capabilityId": { "type": ["string", "null"] },
                    "priorReceiptId": { "type": ["string", "null"] },
                    "requestedEffect": effect_identity_schema(),
                    "authorizedEffect": effect_identity_schema(),
                },
            },

            "checkCorrelation": {
                "type": ["object", "null"], "additionalProperties": false,
                "properties": { "declaredCheckId": { "type": "string", "minLength": 1 }, "method": { "type": "string", "minLength": 1 } },
            },

            "hostEnforcement": {
                "type": "object", "additionalProperties": false, "required": ["capabilities", "knownBypasses"],
                "properties": {
                    "capabilities": { "type": "array", "items": { "type": "string" } },
                    "knownBypasses": { "type": "array", "items": { "type": "string" } },
                },
            },

            "replayNonce": { "type": ["string", "null"] },
            "replaySequence": { "type": ["integer", "null"] },

            "idempotencyKey": { "type": ["string", "null"] },

            "extensions": { "type": "object" },
        },
    })
}

/// Mirrors JS `HOST_EVENT_BOUND_FIELDS`.
pub const HOST_EVENT_BOUND_FIELDS: &[&str] = &[
    "schemaVersion", "kind", "eventId", "eventType", "time",
    "runId", "taskId", "requestId", "contractId", "workspace",
    "operation", "effect", "result", "sourceRevision", "idempotencyKey",
];

/// Structural validation only. Mirrors `validateHostEvent(e)`: rejects a
/// non-object/`null`/array `e` with a single `$:type` issue (matching JS's
/// own short-circuit before it ever calls `validateSchema`), otherwise runs
/// the full `HOST_EVENT_SCHEMA` closed-schema check.
pub fn validate_host_event(e: &Json) -> (bool, Vec<String>) {
    if e.is_null() || !e.is_object() {
        return (false, vec!["$:type".to_string()]);
    }
    let issues = validate_schema(&host_event_schema(), e);
    (issues.is_empty(), issues)
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

    let (valid, issues) = validate_host_event(&candidate);
    if !valid {
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
        let out = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap();
        assert_eq!(out["eventType"], "pre-effect");
    }

    #[test]
    fn rejects_unknown_event_type() {
        let raw = json!({"eventType": "NotARealEvent", "workspace": "/repo"});
        let err = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap_err();
        assert!(err.issues.iter().any(|s| s.contains("eventType")), "{:?}", err.issues);
    }

    #[test]
    fn rejects_empty_workspace() {
        let raw = json!({"eventType": "pre-effect", "workspace": ""});
        let err = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap_err();
        assert!(err.issues.iter().any(|s| s.contains("workspace")), "{:?}", err.issues);
    }

    #[test]
    fn extensions_carried_only_when_present() {
        let raw = json!({"eventType": "Stop", "workspace": "/repo"});
        let out = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap();
        assert!(out.get("extensions").is_none());

        let raw2 = json!({"eventType": "Stop", "workspace": "/repo", "extensions": {"a": 1}});
        let out2 = normalize_host_event(&raw2, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap();
        assert_eq!(out2["extensions"], json!({"a": 1}));
    }

    #[test]
    fn validate_host_event_rejects_non_object() {
        let (valid, issues) = validate_host_event(&Json::Null);
        assert!(!valid);
        assert_eq!(issues, vec!["$:type".to_string()]);
    }

    #[test]
    fn validate_host_event_accepts_normalized_candidate() {
        let raw = json!({"eventType": "Stop", "workspace": "/repo"});
        let out = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap();
        let (valid, issues) = validate_host_event(&out);
        assert!(valid, "{:?}", issues);
    }

    #[test]
    fn validate_host_event_rejects_unknown_field() {
        let raw = json!({"eventType": "Stop", "workspace": "/repo"});
        let mut out = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap();
        out["notAField"] = json!(true);
        let (valid, issues) = validate_host_event(&out);
        assert!(!valid);
        assert!(issues.iter().any(|s| s.contains("notAField")), "{:?}", issues);
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
