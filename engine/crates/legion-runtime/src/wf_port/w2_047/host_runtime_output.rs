//! Faithful port of `src/lib/host/arcane/host-runtime-output.mjs`.
//!
//! JS builds `renderHostRuntimeOutput` on `decision-envelope.mjs`'s
//! `createDecisionEnvelope`/`publicReason`, and asserts the result against
//! the `arcane-host-runtime-output-v1` schema via `RuntimeSchemaSet` before
//! returning it. Both dependencies now have Rust ports this crate can
//! reach: `w2_046::decision_envelope` (wired into `wf_port` in this same
//! crate) and `legion_policy::wf_port::wf068::RuntimeSchemaSet` (this
//! crate already depends on `legion-policy`). `render_host_runtime_output`
//! below keeps the low-level, dependency-free shape logic (which of the
//! three output shapes — `PreToolUse`/`Stop`/other — is produced) behind an
//! injected `envelope_of` closure, since that is exactly the part JS's
//! `renderHostRuntimeOutput` itself owns irrespective of how the envelope
//! was built. `render_host_runtime_output_checked` / `serialize_host_runtime_output_checked`
//! are the fully-wired entry points: they build the envelope with
//! `create_decision_envelope`, run the real schema assertion, and are the
//! faithful equivalent of calling the JS functions directly.

use legion_policy::wf_port::wf068::{ArcaneError as SchemaError, RuntimeSchemaSet};
use serde_json::{json, Value as Json};

use crate::wf_port::w2_046::decision_envelope::{
    create_decision_envelope, DecisionEnvelope as RealDecisionEnvelope, DecisionEnvelopeInput,
};

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
/// injected here rather than built inline. This function does not itself
/// run the `arcane-host-runtime-output-v1` schema assertion JS performs
/// before returning — `render_host_runtime_output_checked` below is the
/// entry point that does, using the real envelope and the real schema.
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
/// the JSON with a trailing newline. Does not itself run the schema
/// assertion — see `serialize_host_runtime_output_checked`.
pub fn serialize_host_runtime_output(output: Option<&Json>) -> String {
    match output {
        None => String::new(),
        Some(v) => format!("{}\n", serde_json::to_string(v).expect("Json::to_string is infallible for valid Value")),
    }
}

/// `$id` of the schema JS's `schema.assert('arcane-host-runtime-output-v1', output)`
/// checks against (`schemas/arcane/host-runtime-output-v1.schema.json`).
pub const HOST_RUNTIME_OUTPUT_SCHEMA_ID: &str = "arcane-host-runtime-output-v1";

fn envelope_to_json(envelope: &RealDecisionEnvelope) -> DecisionEnvelope {
    DecisionEnvelope {
        code: envelope.code.clone(),
        public_reason: envelope.public_reason.clone(),
        enforcement_health: envelope.enforcement_health.clone(),
        retry_signature: envelope.retry_signature.clone().map(Json::from).unwrap_or(Json::Null),
        termination: Json::from(envelope.termination),
        certification: Json::from(envelope.certification.clone()),
        missing_classes: Json::from(envelope.missing_classes.clone()),
        responsible_producer: envelope.responsible_producer.clone().map(Json::from).unwrap_or(Json::Null),
        remediation_routes: Json::from(envelope.remediation_routes.clone()),
        missing_evidence: Json::from(
            envelope
                .missing_evidence
                .iter()
                .map(|e| {
                    json!({
                        "missingClass": e.missing_class,
                        "responsibleProducer": e.responsible_producer,
                        "remediationRoutes": e.remediation_routes,
                    })
                })
                .collect::<Vec<_>>(),
        ),
    }
}

/// Error surface for the fully-wired entry points: either the envelope
/// build fails (unknown missing-evidence class — mirrors JS's thrown
/// `ArcaneError` from `actionableMissingEvidence`), or the rendered output
/// fails its `arcane-host-runtime-output-v1` schema assertion (mirrors JS's
/// `schema.assert` throw).
#[derive(Debug, Clone)]
pub enum HostRuntimeOutputError {
    Envelope(String),
    Schema(SchemaError),
}

impl std::fmt::Display for HostRuntimeOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Envelope(class) => write!(f, "unknown missing-evidence class: {class}"),
            Self::Schema(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for HostRuntimeOutputError {}

/// Fully-wired port of `renderHostRuntimeOutput`: builds the real decision
/// envelope via `create_decision_envelope`, renders the output shape, and
/// asserts it against `arcane-host-runtime-output-v1` — the faithful
/// equivalent of calling the JS function directly (JS renders unconditionally
/// then asserts before returning).
pub fn render_host_runtime_output_checked(
    event_type: &str,
    envelope_input: DecisionEnvelopeInput,
    escalate: bool,
    schema: &RuntimeSchemaSet,
) -> Result<Option<Json>, HostRuntimeOutputError> {
    let allowed = envelope_input.allowed;
    if allowed {
        // Mirrors JS: `if (allowed) return null;` — envelope is never built,
        // matching JS never calling createDecisionEnvelope in that branch.
        return Ok(None);
    }
    let real_envelope = create_decision_envelope(envelope_input)
        .map_err(|e| HostRuntimeOutputError::Envelope(e.0))?;
    let output = render_host_runtime_output(event_type, false, escalate, || envelope_to_json(&real_envelope));
    schema
        .assert(HOST_RUNTIME_OUTPUT_SCHEMA_ID, output.as_ref().unwrap_or(&Json::Null))
        .map_err(HostRuntimeOutputError::Schema)?;
    Ok(output)
}

/// Fully-wired port of `serializeHostRuntimeOutput`: mirrors JS exactly,
/// including that `null` short-circuits to `""` *before* the schema assert
/// (`if (output === null) return ''; schema.assert(...)`) — the assert never
/// runs for the `None` case.
pub fn serialize_host_runtime_output_checked(
    output: Option<&Json>,
    schema: &RuntimeSchemaSet,
) -> Result<String, SchemaError> {
    let Some(v) = output else {
        return Ok(String::new());
    };
    schema.assert(HOST_RUNTIME_OUTPUT_SCHEMA_ID, v)?;
    Ok(serialize_host_runtime_output(output))
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

    // --- fully-wired entry points (real decision envelope + real schema assertion) ---

    fn denied_input(code: &str) -> DecisionEnvelopeInput {
        DecisionEnvelopeInput { allowed: false, code: Some(code.to_string()), ..Default::default() }
    }

    #[test]
    fn checked_allowed_returns_none_without_building_envelope() {
        let schema = RuntimeSchemaSet::new();
        let input = DecisionEnvelopeInput { allowed: true, ..Default::default() };
        let out = render_host_runtime_output_checked("PreToolUse", input, false, &schema).unwrap();
        assert_eq!(out, None);
    }

    #[test]
    fn checked_pre_tool_use_deny_passes_schema() {
        let schema = RuntimeSchemaSet::new();
        let out = render_host_runtime_output_checked("PreToolUse", denied_input("ARC_APPROVAL_REQUIRED"), false, &schema)
            .unwrap()
            .unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(out["code"], "ARC_APPROVAL_REQUIRED");
        assert_eq!(out["missingClasses"], json!([]));
    }

    #[test]
    fn checked_stop_block_passes_schema() {
        let schema = RuntimeSchemaSet::new();
        let out = render_host_runtime_output_checked("Stop", denied_input("ARC_NO_CONTRACT"), false, &schema)
            .unwrap()
            .unwrap();
        assert_eq!(out["decision"], "block");
        assert_eq!(out["reason"], "ARC_NO_CONTRACT: No sealed execution contract is bound.");
    }

    #[test]
    fn checked_other_event_passes_schema() {
        let schema = RuntimeSchemaSet::new();
        let out = render_host_runtime_output_checked("SessionStart", denied_input("ARC_HOST_EVENT_INVALID"), false, &schema)
            .unwrap()
            .unwrap();
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "SessionStart");
        assert!(out["hookSpecificOutput"]["additionalContext"].as_str().unwrap().starts_with("Arcane: "));
    }

    #[test]
    fn checked_unknown_missing_class_is_envelope_error() {
        let schema = RuntimeSchemaSet::new();
        let input = DecisionEnvelopeInput {
            allowed: false,
            code: Some("ARC_EVIDENCE_INSUFFICIENT".to_string()),
            detail: crate::wf_port::w2_046::decision_envelope::DecisionEnvelopeDetail {
                missing_classes: vec!["not-a-real-class".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = render_host_runtime_output_checked("PreToolUse", input, false, &schema).unwrap_err();
        assert!(matches!(err, HostRuntimeOutputError::Envelope(c) if c == "not-a-real-class"));
    }

    #[test]
    fn serialize_checked_round_trips_through_schema() {
        let schema = RuntimeSchemaSet::new();
        let out = render_host_runtime_output_checked("Stop", denied_input("ARC_NO_CONTRACT"), false, &schema)
            .unwrap();
        let text = serialize_host_runtime_output_checked(out.as_ref(), &schema).unwrap();
        assert!(text.ends_with('\n'));
        assert_eq!(text.trim_end(), serde_json::to_string(out.as_ref().unwrap()).unwrap());
    }

    #[test]
    fn serialize_checked_none_is_empty_and_schema_accepts_null() {
        let schema = RuntimeSchemaSet::new();
        assert_eq!(serialize_host_runtime_output_checked(None, &schema).unwrap(), "");
    }
}
