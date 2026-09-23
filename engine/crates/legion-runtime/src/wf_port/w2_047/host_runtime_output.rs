//! Faithful port of `src/lib/host/arcane/host-runtime-output.mjs`.
//!
//! JS builds `renderHostRuntimeOutput` on `decision-envelope.mjs`'s
//! `createDecisionEnvelope`/`publicReason`. This chunk does not own that
//! module (see `wf_port::w2_047` module docs), so the envelope is taken as
//! an injected closure (`envelope_of`) rather than a hard dependency on the
//! in-flight, not-yet-wired `w2_046::decision_envelope` port. An integrator
//! wiring both chunks should pass a closure built from
//! `w2_046::decision_envelope::{create_decision_envelope, public_reason}`
//! for byte-identical behavior; this port reproduces exactly the part JS's
//! `renderHostRuntimeOutput` itself owns — which of the three output shapes
//! (`PreToolUse`/`Stop`/other) is produced, and the `serializeHostRuntimeOutput`
//! trailing-newline/empty-string behavior.

use serde_json::{json, Value as Json};

/// The subset of a decision envelope `renderHostRuntimeOutput` actually
/// reads. Mirrors `createDecisionEnvelope(...)`'s returned shape as consumed
/// by `publicDetail` in the JS source.
#[derive(Debug, Clone)]
pub struct DecisionEnvelope {
    pub code: Option<String>,
    pub public_reason: String,
    pub enforcement_health: String,
    pub retry_signature: Json,
    pub termination: Json,
    pub certification: Json,
    pub missing_classes: Json,
    pub responsible_producer: Json,
    pub remediation_routes: Json,
    pub missing_evidence: Json,
}

impl DecisionEnvelope {
    fn public_detail(&self) -> Json {
        json!({
            "code": self.code,
            "publicReason": self.public_reason,
            "enforcementHealth": self.enforcement_health,
            "retrySignature": self.retry_signature,
            "termination": self.termination,
            "certification": self.certification,
            "missingClasses": self.missing_classes,
            "responsibleProducer": self.responsible_producer,
            "remediationRoutes": self.remediation_routes,
            "missingEvidence": self.missing_evidence,
        })
    }
}

/// Mirrors `renderHostRuntimeOutput({eventType, allowed, code, detail,
/// enforcementHealth, escalate})`. Returns `None` when `allowed` (JS:
/// `return null`). `envelope_of` mirrors `createDecisionEnvelope({allowed,
/// code, detail, enforcementHealth})` — see the module doc for why it is
/// injected. Schema assertion against `arcane-host-runtime-output-v1`
/// (`RuntimeSchemaSet`) is out of this chunk's budget and is not reproduced;
/// callers that need it should assert the returned JSON shape themselves.
#[allow(clippy::too_many_arguments)]
pub fn render_host_runtime_output(
    event_type: &str,
    allowed: bool,
    escalate: bool,
    envelope_of: impl FnOnce() -> DecisionEnvelope,
) -> Option<Json> {
    if allowed {
        return None;
    }
    let envelope = envelope_of();
    let reason = envelope.public_reason.clone();
    let detail = envelope.public_detail();
    let mut output = match event_type {
        "PreToolUse" => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": if escalate { "ask" } else { "deny" },
                "permissionDecisionReason": reason,
            },
        }),
        "Stop" => json!({
            "decision": "block",
            "reason": reason,
        }),
        other => json!({
            "hookSpecificOutput": {
                "hookEventName": other,
                "additionalContext": format!("Arcane: {reason}"),
            },
        }),
    };
    // Merge `...publicDetail(envelope)` alongside the top-level keys, matching
    // JS's object spread (top-level `detail` fields sit next to
    // `hookSpecificOutput`/`decision`/`reason`).
    if let (Json::Object(out_map), Json::Object(detail_map)) = (&mut output, detail) {
        for (k, v) in detail_map {
            out_map.insert(k, v);
        }
    }
    Some(output)
}

/// Mirrors `serializeHostRuntimeOutput(output)`: `null` -> `""`; otherwise
/// the JSON with a trailing newline. Schema assertion is skipped for the
/// same reason as above.
pub fn serialize_host_runtime_output(output: Option<&Json>) -> String {
    match output {
        None => String::new(),
        Some(v) => format!("{}\n", serde_json::to_string(v).expect("Json::to_string is infallible for valid Value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> DecisionEnvelope {
        DecisionEnvelope {
            code: Some("ARC_APPROVAL_REQUIRED".to_string()),
            public_reason: "ARC_APPROVAL_REQUIRED: Required approval evidence is missing.".to_string(),
            enforcement_health: "strong".to_string(),
            retry_signature: Json::Null,
            termination: Json::Null,
            certification: Json::Null,
            missing_classes: Json::Null,
            responsible_producer: Json::Null,
            remediation_routes: Json::Null,
            missing_evidence: Json::Null,
        }
    }

    #[test]
    fn allowed_returns_none() {
        assert_eq!(render_host_runtime_output("PreToolUse", true, false, envelope), None);
    }

    #[test]
    fn pre_tool_use_deny_shape() {
        let out = render_host_runtime_output("PreToolUse", false, false, envelope).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(out["code"], "ARC_APPROVAL_REQUIRED");
    }

    #[test]
    fn pre_tool_use_escalate_asks() {
        let out = render_host_runtime_output("PreToolUse", false, true, envelope).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn stop_block_shape() {
        let out = render_host_runtime_output("Stop", false, false, envelope).unwrap();
        assert_eq!(out["decision"], "block");
        assert_eq!(out["reason"], "ARC_APPROVAL_REQUIRED: Required approval evidence is missing.");
    }

    #[test]
    fn other_event_shape() {
        let out = render_host_runtime_output("SessionStart", false, false, envelope).unwrap();
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "SessionStart");
        assert_eq!(
            out["hookSpecificOutput"]["additionalContext"],
            "Arcane: ARC_APPROVAL_REQUIRED: Required approval evidence is missing."
        );
    }

    #[test]
    fn serialize_none_is_empty_string() {
        assert_eq!(serialize_host_runtime_output(None), "");
    }

    #[test]
    fn serialize_some_has_trailing_newline() {
        let v = json!({"a": 1});
        let out = serialize_host_runtime_output(Some(&v));
        assert!(out.ends_with('\n'));
        assert_eq!(out.trim_end(), r#"{"a":1}"#);
    }
}
