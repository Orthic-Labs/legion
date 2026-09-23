//! Ported from `src/lib/host/arcane/decision-envelope.mjs`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

pub const DECISION_ENFORCEMENT_HEALTH: [&str; 6] =
    ["strong", "observed", "read_only", "advisory", "unsupported", "degraded"];
pub const DECISION_TERMINATION: [&str; 2] = ["terminate", "continue"];
pub const DECISION_CERTIFICATION: [&str; 4] = ["not_claimed", "genuine", "certified", "rejected"];

static PUBLIC_REASONS: LazyLock<BTreeMap<&'static str, &'static str>> = LazyLock::new(|| {
    [
        ("ARC_SCHEMA_INVALID", "Arcane rejected invalid structured input."),
        ("ARC_ID_INVALID", "Arcane rejected an invalid identifier."),
        ("ARC_CANONICALIZATION_FAILED", "Arcane could not canonicalize required data."),
        ("ARC_POLICY_UNAVAILABLE", "Arcane policy is unavailable."),
        ("ARC_POLICY_MALFORMED", "Arcane policy is invalid."),
        ("ARC_POLICY_UNKNOWN_FIELD", "Arcane policy contains an unknown field."),
        ("ARC_AUTHORITY_NOT_ASSERTED", "Required host authority was not asserted."),
        ("ARC_AUTHORITY_MODEL_CLAIMED", "Authority cannot be claimed by model input."),
        ("ARC_CLAIM_PREREQUISITE_UNMET", "Completion prerequisites are unmet."),
        ("ARC_AUTH_FORGED", "Authentication verification failed."),
        ("ARC_AUTH_UNAUTHENTICATED", "Authenticated host evidence is missing."),
        ("ARC_AUTH_KEY_UNAVAILABLE", "Host authentication key is unavailable."),
        ("ARC_AUTH_LEGACY_DIGEST", "A legacy digest is not authentication."),
        ("ARC_REPLAY_NONCE_SEEN", "Replay nonce was already consumed."),
        ("ARC_REPLAY_SEQUENCE_REGRESSION", "Replay sequence is not increasing."),
        ("ARC_REPLAY_STALE", "Host event is outside the freshness window."),
        ("ARC_BINDING_MISMATCH", "Runtime binding does not match authorization."),
        ("ARC_CAPABILITY_EXPIRED", "Capability expired."),
        ("ARC_CAPABILITY_EXHAUSTED", "Capability was already consumed."),
        ("ARC_CAPABILITY_REVOKED", "Capability was revoked."),
        ("ARC_CAPABILITY_UNKNOWN", "Capability is missing."),
        ("ARC_HOST_EVENT_INVALID", "Host event is invalid."),
        ("ARC_HOST_EVENT_UNTRUSTED", "Host event is not authenticated."),
        ("ARC_MODEL_SELF_REPORT", "Model self-report cannot become a receipt."),
        ("ARC_INGEST_CORRELATION_MISSING", "Matching pre-effect authorization is missing."),
        ("ARC_EVIDENCE_STALE", "Evidence is stale."),
        ("ARC_EVIDENCE_INSUFFICIENT", "Required evidence is missing."),
        ("ARC_DEPENDENCY_UNKNOWN", "Evidence dependency is unknown."),
        ("ARC_STORE_CORRUPT", "Arcane state is unavailable or corrupt."),
        ("ARC_GATE_UNAVAILABLE", "Pre-effect gate is unavailable."),
        ("ARC_NO_CONTRACT", "No sealed execution contract is bound."),
        ("ARC_CONTRACT_NOT_EXECUTABLE", "Execution contract has unresolved questions."),
        ("ARC_CONTRACT_VERSION_MISMATCH", "Bound contract version or digest does not match."),
        ("ARC_PATH_NOT_OWNED", "Target is outside contract-owned scope."),
        ("ARC_PATH_FORBIDDEN", "Target is forbidden by contract."),
        ("ARC_EFFECT_CLASS_UNAUTHORIZED", "Effect class is not authorized."),
        ("ARC_LATITUDE_VIOLATION", "Requested latitude is not allowed."),
        ("ARC_APPROVAL_REQUIRED", "Required approval evidence is missing."),
        ("ARC_KERNEL_PRIMITIVE_UNAVAILABLE", "Required Kernel primitive is unavailable."),
        (
            "ARC_ESCALATION_UNEVIDENCED",
            "Escalation needs two documented self-attempts and the error each one hit, in the prompt body.",
        ),
        (
            "ARC_STOP_SHAPE",
            "[non-authoritative stop feedback] Complete latest user-requested scope; this feedback cannot authorize or restore scope.",
        ),
    ]
    .into_iter()
    .collect()
});

struct Remediation {
    responsible_producer: &'static str,
    remediation_routes: &'static [&'static str],
}

static REMEDIATION: LazyLock<BTreeMap<&'static str, Remediation>> = LazyLock::new(|| {
    [
        (
            "deterministic",
            Remediation { responsible_producer: "legion run close", remediation_routes: &["legion run close --help"] },
        ),
        (
            "terminal-operation-claim",
            Remediation {
                responsible_producer: "legion completion claim",
                remediation_routes: &["legion completion claim --help"],
            },
        ),
        (
            "host-event-ledger",
            Remediation {
                responsible_producer: "authenticated host ingress",
                remediation_routes: &["legion host events inspect"],
            },
        ),
    ]
    .into_iter()
    .collect()
});

/// Port of `publicReason`. `code = None` maps to the JS `code === null`
/// branch ("No denial."); any other unknown code falls back to
/// `ARC_SCHEMA_INVALID`, matching the JS `Object.hasOwn` fallback.
pub fn public_reason(code: Option<&str>) -> String {
    let Some(code) = code else {
        return "ARCANE_OK: No denial.".to_string();
    };
    let resolved = if PUBLIC_REASONS.contains_key(code) { code } else { "ARC_SCHEMA_INVALID" };
    format!("{resolved}: {}", PUBLIC_REASONS[resolved])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingEvidenceEntry {
    pub missing_class: String,
    pub responsible_producer: String,
    pub remediation_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownMissingEvidenceClass(pub String);

/// Port of `actionableMissingEvidence`. `missing_classes` is de-duplicated
/// preserving first-seen order, matching `[...new Set(...)]`. An unknown
/// class is an `ArcaneError('ARC_SCHEMA_INVALID', ...)` in the original;
/// here it is `Err`.
pub fn actionable_missing_evidence(
    missing_classes: &[String],
) -> Result<Vec<MissingEvidenceEntry>, UnknownMissingEvidenceClass> {
    let mut seen = std::collections::BTreeSet::new();
    let mut deduped = Vec::new();
    for c in missing_classes {
        if seen.insert(c.clone()) {
            deduped.push(c.clone());
        }
    }
    deduped
        .into_iter()
        .map(|missing_class| {
            let remediation = REMEDIATION
                .get(missing_class.as_str())
                .ok_or_else(|| UnknownMissingEvidenceClass(missing_class.clone()))?;
            Ok(MissingEvidenceEntry {
                missing_class,
                responsible_producer: remediation.responsible_producer.to_string(),
                remediation_routes: remediation.remediation_routes.iter().map(|s| s.to_string()).collect(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct DecisionEnvelopeDetail {
    pub missing_classes: Vec<String>,
    /// `detail.termination` in JS is either `{ allowed: bool }` or a bare
    /// `'terminate'` string; both shapes collapse to this bool.
    pub termination_terminate: bool,
    pub certification: Option<String>,
    pub retry_signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DecisionEnvelopeInput {
    pub allowed: bool,
    pub code: Option<String>,
    pub detail: DecisionEnvelopeDetail,
    /// Defaults to `"strong"`, matching the JS default parameter.
    pub enforcement_health: Option<String>,
}

impl Default for DecisionEnvelopeInput {
    fn default() -> Self {
        Self {
            allowed: false,
            code: None,
            detail: DecisionEnvelopeDetail::default(),
            enforcement_health: Some("strong".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEnvelope {
    pub schema_version: u32,
    pub kind: &'static str,
    pub allowed: bool,
    pub code: Option<String>,
    pub public_reason: String,
    pub enforcement_health: String,
    pub retry_signature: Option<String>,
    pub termination: &'static str,
    pub certification: String,
    pub missing_classes: Vec<String>,
    pub responsible_producer: Option<String>,
    pub remediation_routes: Vec<String>,
    pub missing_evidence: Vec<MissingEvidenceEntry>,
}

/// Port of `createDecisionEnvelope`. Returns `Err` when a missing-evidence
/// class has no public remediation, mirroring the thrown `ArcaneError` in
/// `actionableMissingEvidence`.
pub fn create_decision_envelope(
    input: DecisionEnvelopeInput,
) -> Result<DecisionEnvelope, UnknownMissingEvidenceClass> {
    let missing_evidence = actionable_missing_evidence(&input.detail.missing_classes)?;
    let first = missing_evidence.first();
    let termination = if input.detail.termination_terminate { "terminate" } else { "continue" };
    let certification = input
        .detail
        .certification
        .as_deref()
        .filter(|c| DECISION_CERTIFICATION.contains(c))
        .map(|c| c.to_string())
        .unwrap_or_else(|| if input.allowed { "certified".to_string() } else { "rejected".to_string() });
    let enforcement_health = input
        .enforcement_health
        .as_deref()
        .filter(|h| DECISION_ENFORCEMENT_HEALTH.contains(h))
        .unwrap_or("unsupported")
        .to_string();
    Ok(DecisionEnvelope {
        schema_version: 1,
        kind: "arcane-decision-envelope",
        allowed: input.allowed,
        code: input.code.clone(),
        public_reason: public_reason(input.code.as_deref()),
        enforcement_health,
        retry_signature: input.detail.retry_signature.clone(),
        termination,
        certification,
        missing_classes: missing_evidence.iter().map(|e| e.missing_class.clone()).collect(),
        responsible_producer: first.map(|e| e.responsible_producer.clone()),
        remediation_routes: first.map(|e| e.remediation_routes.clone()).unwrap_or_default(),
        missing_evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_reason_none_is_no_denial() {
        assert_eq!(public_reason(None), "ARCANE_OK: No denial.");
    }

    #[test]
    fn public_reason_unknown_code_falls_back() {
        let r = public_reason(Some("NOT_A_REAL_CODE"));
        assert!(r.starts_with("ARC_SCHEMA_INVALID:"));
    }

    #[test]
    fn public_reason_known_code() {
        assert_eq!(
            public_reason(Some("ARC_AUTH_FORGED")),
            "ARC_AUTH_FORGED: Authentication verification failed."
        );
    }

    #[test]
    fn actionable_missing_evidence_dedupes_and_resolves() {
        let classes = vec!["deterministic".to_string(), "deterministic".to_string(), "host-event-ledger".to_string()];
        let out = actionable_missing_evidence(&classes).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].missing_class, "deterministic");
        assert_eq!(out[0].responsible_producer, "legion run close");
        assert_eq!(out[1].missing_class, "host-event-ledger");
    }

    #[test]
    fn actionable_missing_evidence_unknown_class_errors() {
        let err = actionable_missing_evidence(&["not-a-class".to_string()]).unwrap_err();
        assert_eq!(err.0, "not-a-class");
    }

    #[test]
    fn envelope_allowed_defaults_certified_continue() {
        let env = create_decision_envelope(DecisionEnvelopeInput {
            allowed: true,
            code: None,
            detail: DecisionEnvelopeDetail::default(),
            enforcement_health: Some("strong".to_string()),
        })
        .unwrap();
        assert!(env.allowed);
        assert_eq!(env.certification, "certified");
        assert_eq!(env.termination, "continue");
        assert_eq!(env.public_reason, "ARCANE_OK: No denial.");
        assert!(env.missing_evidence.is_empty());
        assert_eq!(env.responsible_producer, None);
    }

    #[test]
    fn envelope_denied_with_missing_evidence_surfaces_first_remediation() {
        let env = create_decision_envelope(DecisionEnvelopeInput {
            allowed: false,
            code: Some("ARC_EVIDENCE_INSUFFICIENT".to_string()),
            detail: DecisionEnvelopeDetail {
                missing_classes: vec!["host-event-ledger".to_string(), "deterministic".to_string()],
                termination_terminate: true,
                certification: None,
                retry_signature: Some("sig-1".to_string()),
            },
            enforcement_health: Some("degraded".to_string()),
        })
        .unwrap();
        assert!(!env.allowed);
        assert_eq!(env.certification, "rejected");
        assert_eq!(env.termination, "terminate");
        assert_eq!(env.enforcement_health, "degraded");
        assert_eq!(env.retry_signature, Some("sig-1".to_string()));
        assert_eq!(env.responsible_producer, Some("authenticated host ingress".to_string()));
        assert_eq!(env.missing_classes, vec!["host-event-ledger", "deterministic"]);
    }

    #[test]
    fn envelope_invalid_enforcement_health_falls_back_to_unsupported() {
        let env = create_decision_envelope(DecisionEnvelopeInput {
            allowed: true,
            code: None,
            detail: DecisionEnvelopeDetail::default(),
            enforcement_health: Some("bogus".to_string()),
        })
        .unwrap();
        assert_eq!(env.enforcement_health, "unsupported");
    }
}
