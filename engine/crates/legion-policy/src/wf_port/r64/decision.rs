//! Port of the `decision(...)` helper and its result shape from
//! `src/lib/contracts/arcane/errors.mjs`. Shared by every module in this
//! packet (`advisory_profile`, `completion_gate`,
//! `current_user_risk_acceptance`, `gate_validity`) that returns Arcane's
//! typed decision.
//!
//! `FAIL_CLOSED_CODES` and the `ARCANE_ERROR_CODE` closed set both live in
//! `errors.mjs` in full (145 lines covering every Arcane error code across
//! every subsystem); porting the entire closed set is out of this packet's
//! file list. This port keeps the exact `decision()` field shape
//! (`allowed`, `code`, `message`, `detail`, `failClosed`,
//! `enforcementHealth`, `escalate`) and the exact `failClosed` derivation
//! for every code this packet's modules actually emit (checked against
//! `FAIL_CLOSED_CODES` in the JS source one at a time below), rather than
//! reproducing the full code enum.

use serde_json::{json, Value};

/// Codes this packet's modules emit that JS's `FAIL_CLOSED_CODES` marks
/// `failClosed: true`. Checked against `errors.mjs`'s `FAIL_CLOSED_CODES`
/// set: `ARC_STORE_CORRUPT` is the only one of those seven codes this
/// packet's decision sites can produce.
const FAIL_CLOSED_CODES: &[&str] = &["ARC_STORE_CORRUPT"];

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: String,
    pub detail: Value,
    pub fail_closed: bool,
    pub enforcement_health: String,
    pub escalate: bool,
}

/// Mirrors JS `decision({ allowed, code, message, detail, enforcementHealth, escalate })`.
/// `enforcement_health` defaults to `"strong"` and `escalate` to `false`,
/// matching the JS defaults exactly.
pub fn decision(
    allowed: bool,
    code: Option<&'static str>,
    message: impl Into<String>,
    detail: Value,
) -> Decision {
    decision_full(allowed, code, message, detail, "strong", false)
}

pub fn decision_full(
    allowed: bool,
    code: Option<&'static str>,
    message: impl Into<String>,
    detail: Value,
    enforcement_health: impl Into<String>,
    escalate: bool,
) -> Decision {
    Decision {
        allowed,
        code,
        message: message.into(),
        detail: if detail.is_null() { json!({}) } else { detail },
        fail_closed: code.map(|c| FAIL_CLOSED_CODES.contains(&c)).unwrap_or(false),
        enforcement_health: enforcement_health.into(),
        escalate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_has_no_fail_closed() {
        let d = decision(true, None, "ok", json!({}));
        assert!(d.allowed);
        assert!(!d.fail_closed);
        assert_eq!(d.enforcement_health, "strong");
        assert!(!d.escalate);
    }

    #[test]
    fn store_corrupt_is_fail_closed() {
        let d = decision(false, Some("ARC_STORE_CORRUPT"), "corrupt", json!({}));
        assert!(d.fail_closed);
    }

    #[test]
    fn evidence_insufficient_is_not_fail_closed() {
        let d = decision(false, Some("ARC_EVIDENCE_INSUFFICIENT"), "missing", json!({}));
        assert!(!d.fail_closed);
    }
}
