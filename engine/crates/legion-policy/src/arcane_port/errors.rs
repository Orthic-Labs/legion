//! Faithful port of `src/lib/contracts/arcane/errors.mjs`.
//!
//! Arcane's typed error taxonomy. Arcane is deterministic code on the host
//! boundary: it never returns an untyped string and never degrades silently.
//! Every refusal carries a machine-readable `code`, the subject it refused,
//! and whether the refusal was a *fail-closed* (enforcement unavailable) or a
//! *denial* (enforcement available and the request lost).
//!
//! Source: `src/lib/contracts/arcane/errors.mjs` (ARCANE_ERROR_CODE,
//! ArcaneError, FAIL_CLOSED_CODES, arcErr, decision, ENFORCEMENT_LEVEL).

use std::collections::BTreeMap;
use std::fmt;

/// Every code Arcane can emit. Closed set — adding one is an API change.
/// Order and membership match `ARCANE_ERROR_CODE` in the JS source exactly.
pub const ARCANE_ERROR_CODE: &[&str] = &[
    // structural / contract
    "ARC_SCHEMA_INVALID",
    "ARC_ID_INVALID",
    "ARC_CANONICALIZATION_FAILED",
    // policy plane (S02)
    "ARC_POLICY_UNAVAILABLE",
    "ARC_POLICY_MALFORMED",
    "ARC_POLICY_UNKNOWN_FIELD",
    "ARC_AUTHORITY_NOT_ASSERTED",
    "ARC_AUTHORITY_MODEL_CLAIMED",
    "ARC_CLAIM_PREREQUISITE_UNMET",
    // authentication / replay (S03)
    "ARC_AUTH_FORGED",
    "ARC_AUTH_UNAUTHENTICATED",
    "ARC_AUTH_KEY_UNAVAILABLE",
    "ARC_AUTH_LEGACY_DIGEST",
    "ARC_REPLAY_NONCE_SEEN",
    "ARC_REPLAY_SEQUENCE_REGRESSION",
    "ARC_REPLAY_STALE",
    "ARC_BINDING_MISMATCH",
    "ARC_CAPABILITY_EXPIRED",
    "ARC_CAPABILITY_EXHAUSTED",
    "ARC_CAPABILITY_REVOKED",
    "ARC_CAPABILITY_UNKNOWN",
    // host ingestion (S04)
    "ARC_HOST_EVENT_INVALID",
    "ARC_HOST_EVENT_UNTRUSTED",
    "ARC_MODEL_SELF_REPORT",
    "ARC_INGEST_CORRELATION_MISSING",
    // evidence / invalidation (S05)
    "ARC_EVIDENCE_STALE",
    "ARC_EVIDENCE_INSUFFICIENT",
    "ARC_UNSOUND_SEAL",
    "ARC_GATE_INVALID",
    "ARC_SELF_CERTIFICATION",
    "ARC_DEPENDENCY_UNKNOWN",
    "ARC_STORE_CORRUPT",
    "ARC_STORE_MISSING",
    // pre-effect gate (deliverable 6)
    "ARC_GATE_UNAVAILABLE",
    "ARC_NO_CONTRACT",
    "ARC_CONTRACT_NOT_EXECUTABLE",
    "ARC_CONTRACT_VERSION_MISMATCH",
    "ARC_PROFILE_BINDING_MISMATCH",
    "ARC_PROFILE_EFFECT_FORBIDDEN",
    "ARC_PATH_NOT_OWNED",
    "ARC_PATH_FORBIDDEN",
    "ARC_EFFECT_CLASS_UNAUTHORIZED",
    "ARC_LATITUDE_VIOLATION",
    "ARC_APPROVAL_REQUIRED",
    // kernel dependency (Wave-2 sequencing)
    "ARC_KERNEL_PRIMITIVE_UNAVAILABLE",
    // escalation ladder (absorbed from gate_codex_escalation.py)
    "ARC_ESCALATION_UNEVIDENCED",
];

/// Codes whose refusal means enforcement itself was unavailable (mutation
/// fails closed), distinct from a denial where enforcement ran and said no.
/// Matches `FAIL_CLOSED_CODES` in the JS source exactly.
pub const FAIL_CLOSED_CODES: &[&str] = &[
    "ARC_POLICY_UNAVAILABLE",
    "ARC_POLICY_MALFORMED",
    "ARC_POLICY_UNKNOWN_FIELD",
    "ARC_AUTH_KEY_UNAVAILABLE",
    "ARC_GATE_UNAVAILABLE",
    "ARC_STORE_CORRUPT",
    "ARC_KERNEL_PRIMITIVE_UNAVAILABLE",
];

/// Enforcement levels Arcane may honestly report.
pub const ENFORCEMENT_LEVEL: &[&str] = &["strong", "observed", "read_only", "advisory", "unsupported"];

pub fn is_known_code(code: &str) -> bool {
    ARCANE_ERROR_CODE.contains(&code)
}

pub fn is_fail_closed(code: &str) -> bool {
    FAIL_CLOSED_CODES.contains(&code)
}

/// Structured detail bag attached to a refusal. Mirrors the JS `detail`
/// object: an arbitrary, frozen, string-keyed map of string values.
pub type Detail = BTreeMap<String, String>;

/// Arcane's typed error. Mirrors the JS `ArcaneError` class: constructing one
/// with an unknown code is itself a programmer error (`TypeError` in JS),
/// represented here as `Err` from the fallible constructor rather than a
/// panic, since Rust has no exception-based "this can never legally happen"
/// escape hatch at construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcaneError {
    pub code: &'static str,
    pub message: String,
    pub detail: Detail,
    /// true when the refusal is because enforcement itself was unavailable.
    pub fail_closed: bool,
}

/// Returned by `ArcaneError::new` when the caller passes a code outside the
/// closed `ARCANE_ERROR_CODE` set. Mirrors the JS `TypeError` thrown by the
/// `ArcaneError` constructor and by `decision()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownErrorCode(pub String);

impl fmt::Display for UnknownErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown ArcaneError code: {}", self.0)
    }
}

impl std::error::Error for UnknownErrorCode {}

impl ArcaneError {
    /// `code` must be a static string drawn from `ARCANE_ERROR_CODE` (use one
    /// of the constants above, not an arbitrary `&str`, so the closed set is
    /// enforced at the type level for callers within this crate; the runtime
    /// check below still guards values threaded through from elsewhere, e.g.
    /// deserialized JSON).
    pub fn new(code: &'static str, message: impl Into<String>, detail: Detail) -> Result<Self, UnknownErrorCode> {
        if !is_known_code(code) {
            return Err(UnknownErrorCode(code.to_string()));
        }
        Ok(Self {
            code,
            message: message.into(),
            detail,
            fail_closed: is_fail_closed(code),
        })
    }

    pub fn to_json(&self) -> BTreeMap<&'static str, String> {
        let mut m = BTreeMap::new();
        m.insert("code", self.code.to_string());
        m.insert("message", self.message.clone());
        m.insert("failClosed", self.fail_closed.to_string());
        m
    }
}

impl fmt::Display for ArcaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ArcaneError {}

/// Convenience constructor. Mirrors JS `arcErr`.
pub fn arc_err(code: &'static str, message: impl Into<String>, detail: Detail) -> Result<ArcaneError, UnknownErrorCode> {
    ArcaneError::new(code, message, detail)
}

/// A typed decision record. Every Arcane gate returns one of these rather
/// than throwing on denial — a denial is data the caller must record, not an
/// exception it may swallow. Mirrors JS `decision()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: String,
    pub detail: Detail,
    pub fail_closed: bool,
    pub enforcement_health: String,
    /// Routes a refusal to the host's own operator prompt rather than a flat
    /// denial. Never widens a decision: the effect is still refused here,
    /// and only an explicit operator answer at the host can release it.
    pub escalate: bool,
}

#[derive(Debug, Default, Clone)]
pub struct DecisionArgs {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: String,
    pub detail: Detail,
    pub enforcement_health: Option<String>,
    pub escalate: bool,
}

pub fn decision(args: DecisionArgs) -> Result<Decision, UnknownErrorCode> {
    if !args.allowed {
        if let Some(code) = args.code {
            if !is_known_code(code) {
                return Err(UnknownErrorCode(code.to_string()));
            }
        }
    }
    let fail_closed = args.code.map(is_fail_closed).unwrap_or(false);
    Ok(Decision {
        allowed: args.allowed,
        code: args.code,
        message: args.message,
        detail: args.detail,
        fail_closed,
        enforcement_health: args.enforcement_health.unwrap_or_else(|| "strong".to_string()),
        escalate: args.escalate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parity fixture: the JS ARCANE_ERROR_CODE set has exactly 44 entries.
    #[test]
    fn error_code_set_matches_js_cardinality() {
        assert_eq!(ARCANE_ERROR_CODE.len(), 44);
        assert_eq!(FAIL_CLOSED_CODES.len(), 7);
        assert_eq!(ENFORCEMENT_LEVEL.len(), 5);
    }

    #[test]
    fn all_fail_closed_codes_are_known_codes() {
        for c in FAIL_CLOSED_CODES {
            assert!(is_known_code(c), "{c} must be in ARCANE_ERROR_CODE");
        }
    }

    #[test]
    fn new_rejects_unknown_code() {
        let err = ArcaneError::new("ARC_NOT_A_REAL_CODE", "nope", Detail::new());
        assert_eq!(err, Err(UnknownErrorCode("ARC_NOT_A_REAL_CODE".to_string())));
    }

    #[test]
    fn new_computes_fail_closed_from_code() {
        let e = ArcaneError::new("ARC_POLICY_UNAVAILABLE", "no bundle", Detail::new()).unwrap();
        assert!(e.fail_closed);

        let e2 = ArcaneError::new("ARC_REPLAY_STALE", "too old", Detail::new()).unwrap();
        assert!(!e2.fail_closed);
    }

    #[test]
    fn decision_denial_requires_known_code() {
        let d = decision(DecisionArgs {
            allowed: false,
            code: Some("ARC_BOGUS"),
            ..Default::default()
        });
        assert!(d.is_err());
    }

    #[test]
    fn decision_allowed_true_ignores_missing_code() {
        let d = decision(DecisionArgs {
            allowed: true,
            code: None,
            message: "ok".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(d.allowed);
        assert!(!d.fail_closed);
        assert_eq!(d.enforcement_health, "strong");
        assert!(!d.escalate);
    }

    #[test]
    fn decision_fail_closed_follows_code() {
        let d = decision(DecisionArgs {
            allowed: false,
            code: Some("ARC_GATE_UNAVAILABLE"),
            message: "gate down".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(!d.allowed);
        assert!(d.fail_closed);
    }

    #[test]
    fn to_json_round_trips_core_fields() {
        let e = ArcaneError::new("ARC_STORE_CORRUPT", "digest chain broken", Detail::new()).unwrap();
        let j = e.to_json();
        assert_eq!(j.get("code").map(String::as_str), Some("ARC_STORE_CORRUPT"));
        assert_eq!(j.get("failClosed").map(String::as_str), Some("true"));
    }
}
