//! Partial port of `src/lib/host/arcane/denial-circuit.mjs`.
//!
//! EC-603 T-4 — one authenticated retry circuit for conversational denials.
//! It is intentionally not an authorization mechanism: opening it releases
//! only conversation termination; the original denial remains false in every
//! path.
//!
//! ## What is ported here
//! - `denialControlClass` (pure classification) — full fidelity.
//! - `circuitFingerprint`'s digest shape — full fidelity, via
//!   `wf_port::w2_046::canonical::digest_value`.
//! - `applyDenialCircuit`'s merge/decision logic, generalized over a
//!   `DenialRecorder` trait so it can be tested without a real store.
//!
//! ## What is NOT ported (left `NOT-STARTED`, out of this chunk's owned
//! files)
//! The JS `DenialCircuit` class persists HMAC-authenticated receipts to disk
//! (`node:fs`, `node:crypto`) using the shared `signRecord`/`verifyRecord`
//! machinery from `src/lib/guard/compat/audit/receipt-auth.mjs`, which is
//! not part of this chunk (`codex-escalation.mjs`, `continuity.mjs`,
//! `decision-envelope.mjs`, `denial-circuit.mjs`,
//! `discipline-controls.mjs`). Porting a byte-faithful equivalent needs:
//!   - `receipt-auth.mjs`'s `signRecord`/`verifyRecord` (HMAC-SHA256 over a
//!     bound-field projection, keyed by a `keyRing`/`keyId`) — not yet
//!     ported to Rust anywhere reachable from `legion-runtime`.
//!   - an `hmac` crate dependency: `legion-runtime/Cargo.toml` currently
//!     depends on `sha2` but not `hmac`. **Cargo.toml patch needed** (see
//!     this chunk's report) to add:
//!     ```toml
//!     hmac = { workspace = true }
//!     ```
//!     (`hmac 0.13.0` is already in `engine/Cargo.lock` as a transitive
//!     dependency, so pinning it in the workspace `[workspace.dependencies]`
//!     and this crate's `[dependencies]` should resolve without a version
//!     bump elsewhere.)
//! A `DenialRecorder` implementation backed by that machinery can then
//! satisfy the trait below without touching `apply_denial_circuit`.

use super::canonical::digest_value;
use serde_json::{json, Value};

/// Port of `denialControlClass`.
#[derive(Debug, Clone, Default)]
pub struct DenialClassificationInput<'a> {
    pub event_type: Option<&'a str>,
    pub code: Option<&'a str>,
    pub control_class: Option<&'a str>,
}

pub fn denial_control_class(input: DenialClassificationInput<'_>) -> String {
    if let Some(c) = input.control_class {
        return c.to_string();
    }
    if matches!(input.event_type, Some("PreToolUse") | Some("PostToolUse") | Some("PostToolUseFailure")) {
        return "effect".to_string();
    }
    if let Some(code) = input.code {
        let is_security = code.starts_with("ARC_AUTH_")
            || code.starts_with("ARC_BINDING_")
            || code.starts_with("ARC_REPLAY_")
            || code.starts_with("ARC_CAPABILITY_")
            || code.starts_with("ARC_HOST_EVENT_")
            || code == "ARC_STORE_CORRUPT";
        if is_security {
            return "security".to_string();
        }
        if code == "ARC_ESCALATION_UNEVIDENCED" {
            return "escalation".to_string();
        }
        if code == "ARC_STOP_SHAPE" {
            return "stop".to_string();
        }
    }
    "evidence".to_string()
}

pub const MAX_IDENTICAL_DENIALS: u32 = 2;

/// Port of `circuitFingerprint`.
pub fn circuit_fingerprint(
    session_id: &str,
    run_id: &str,
    task_id: &str,
    control_class: &str,
    code: &str,
    missing_evidence_digest: &str,
    target_digest: &str,
) -> String {
    digest_value(&json!({
        "sessionId": session_id,
        "runId": run_id,
        "taskId": task_id,
        "controlClass": control_class,
        "code": code,
        "missingEvidenceDigest": missing_evidence_digest,
        "targetDigest": target_digest,
    }))
}

#[derive(Debug, Clone)]
pub struct DenialRecord {
    pub session_id: String,
    pub run_id: String,
    pub task_id: String,
    pub control_class: String,
    pub code: String,
    pub missing_evidence: Vec<String>,
    pub target: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct DenialReceipt {
    pub fingerprint: String,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct RecordOutcome {
    pub receipt: DenialReceipt,
    pub opened: bool,
}

/// Trait a durable, authenticated denial-circuit store must satisfy for
/// `apply_denial_circuit` to use it. The JS `DenialCircuit` class is the
/// reference implementation (see module docs for the still-needed Rust
/// equivalent).
pub trait DenialRecorder {
    type Error;
    fn record(&mut self, record: DenialRecord) -> Result<RecordOutcome, Self::Error>;
}

/// An in-memory, unauthenticated `DenialRecorder` used for testing
/// `apply_denial_circuit`'s decision logic. It reproduces the JS
/// `record()` counting rule (repeat the same fingerprint up to
/// `MAX_IDENTICAL_DENIALS`, opened only for non-`effect`/`security` control
/// classes) without persistence or HMAC authentication.
#[derive(Debug, Default)]
pub struct MemoryDenialCircuit {
    // keyed by (sessionId, runId, taskId)
    store: std::collections::HashMap<(String, String, String), (String, u32)>,
}

impl DenialRecorder for MemoryDenialCircuit {
    type Error = std::convert::Infallible;

    fn record(&mut self, record: DenialRecord) -> Result<RecordOutcome, Self::Error> {
        let missing_evidence_digest = {
            let mut sorted = record.missing_evidence.clone();
            sorted.sort();
            digest_value(&json!(sorted))
        };
        let target_digest = digest_value(&record.target.clone().unwrap_or(Value::Null));
        let fingerprint = circuit_fingerprint(
            &record.session_id,
            &record.run_id,
            &record.task_id,
            &record.control_class,
            &record.code,
            &missing_evidence_digest,
            &target_digest,
        );
        let scope = (record.session_id.clone(), record.run_id.clone(), record.task_id.clone());
        let prior = self.store.get(&scope).cloned();
        let count = match &prior {
            Some((prior_fp, prior_count)) if *prior_fp == fingerprint => {
                (prior_count + 1).min(MAX_IDENTICAL_DENIALS)
            }
            _ => 1,
        };
        self.store.insert(scope, (fingerprint.clone(), count));
        let opened = count >= MAX_IDENTICAL_DENIALS
            && !matches!(record.control_class.as_str(), "effect" | "security");
        Ok(RecordOutcome { receipt: DenialReceipt { fingerprint, count }, opened })
    }
}

#[derive(Debug, Clone)]
pub struct DenialResult {
    pub allowed: bool,
    pub code: Option<String>,
    pub message: Option<String>,
    pub enforcement_health: Option<String>,
    pub missing_classes: Vec<String>,
    pub target: Option<Value>,
    pub termination_terminate: bool,
    pub retry_signature: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DenialContext<'a> {
    pub event_type: Option<&'a str>,
    pub control_class: Option<&'a str>,
    pub session_id: String,
    pub run_id: String,
    pub task_id: String,
}

/// Port of `applyDenialCircuit`: preserve denial while exposing an
/// authenticated retry signature. When `result.allowed` is true, or no
/// circuit is supplied, the result passes through unchanged (mirroring the
/// JS early return).
pub fn apply_denial_circuit<R: DenialRecorder>(
    mut result: DenialResult,
    circuit: Option<&mut R>,
    context: DenialContext<'_>,
) -> Result<DenialResult, R::Error> {
    let Some(circuit) = circuit else {
        return Ok(result);
    };
    if result.allowed {
        return Ok(result);
    }
    let control_class = denial_control_class(DenialClassificationInput {
        event_type: context.event_type,
        code: result.code.as_deref(),
        control_class: context.control_class,
    });
    let outcome = circuit.record(DenialRecord {
        session_id: context.session_id,
        run_id: context.run_id,
        task_id: context.task_id,
        control_class,
        code: result.code.clone().unwrap_or_default(),
        missing_evidence: result.missing_classes.clone(),
        target: result.target.clone(),
    })?;
    result.retry_signature = Some(outcome.receipt.fingerprint);
    if outcome.opened {
        result.termination_terminate = true;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_class_prefers_explicit_override() {
        let class = denial_control_class(DenialClassificationInput {
            event_type: Some("PreToolUse"),
            code: None,
            control_class: Some("custom"),
        });
        assert_eq!(class, "custom");
    }

    #[test]
    fn control_class_from_event_type() {
        for et in ["PreToolUse", "PostToolUse", "PostToolUseFailure"] {
            let class = denial_control_class(DenialClassificationInput {
                event_type: Some(et),
                code: None,
                control_class: None,
            });
            assert_eq!(class, "effect");
        }
    }

    #[test]
    fn control_class_from_security_code_prefixes() {
        for code in ["ARC_AUTH_FORGED", "ARC_BINDING_MISMATCH", "ARC_REPLAY_STALE", "ARC_CAPABILITY_EXPIRED", "ARC_HOST_EVENT_INVALID", "ARC_STORE_CORRUPT"] {
            let class = denial_control_class(DenialClassificationInput { event_type: None, code: Some(code), control_class: None });
            assert_eq!(class, "security", "code={code}");
        }
    }

    #[test]
    fn control_class_escalation_and_stop() {
        assert_eq!(
            denial_control_class(DenialClassificationInput { event_type: None, code: Some("ARC_ESCALATION_UNEVIDENCED"), control_class: None }),
            "escalation"
        );
        assert_eq!(
            denial_control_class(DenialClassificationInput { event_type: None, code: Some("ARC_STOP_SHAPE"), control_class: None }),
            "stop"
        );
    }

    #[test]
    fn control_class_default_is_evidence() {
        assert_eq!(
            denial_control_class(DenialClassificationInput { event_type: None, code: Some("ARC_EVIDENCE_STALE"), control_class: None }),
            "evidence"
        );
    }

    fn base_result() -> DenialResult {
        DenialResult {
            allowed: false,
            code: Some("ARC_EVIDENCE_STALE".to_string()),
            message: Some("stale".to_string()),
            enforcement_health: Some("strong".to_string()),
            missing_classes: vec!["deterministic".to_string()],
            target: None,
            termination_terminate: false,
            retry_signature: None,
        }
    }

    #[test]
    fn allowed_result_passes_through_unchanged() {
        let mut circuit = MemoryDenialCircuit::default();
        let mut result = base_result();
        result.allowed = true;
        let out = apply_denial_circuit(
            result.clone(),
            Some(&mut circuit),
            DenialContext { session_id: "s".into(), run_id: "r".into(), task_id: "t".into(), ..Default::default() },
        )
        .unwrap();
        assert_eq!(out.retry_signature, None);
    }

    #[test]
    fn no_circuit_passes_through_unchanged() {
        let result = base_result();
        let out = apply_denial_circuit::<MemoryDenialCircuit>(
            result.clone(),
            None,
            DenialContext { session_id: "s".into(), run_id: "r".into(), task_id: "t".into(), ..Default::default() },
        )
        .unwrap();
        assert_eq!(out.retry_signature, None);
    }

    #[test]
    fn repeated_identical_denials_open_after_max() {
        let mut circuit = MemoryDenialCircuit::default();
        let ctx = || DenialContext { session_id: "s".into(), run_id: "r".into(), task_id: "t".into(), ..Default::default() };
        let r1 = apply_denial_circuit(base_result(), Some(&mut circuit), ctx()).unwrap();
        assert!(!r1.termination_terminate);
        let r2 = apply_denial_circuit(base_result(), Some(&mut circuit), ctx()).unwrap();
        assert!(r2.termination_terminate);
        assert_eq!(r1.retry_signature, r2.retry_signature);
    }

    #[test]
    fn effect_and_security_classes_never_open() {
        let mut circuit = MemoryDenialCircuit::default();
        let mut result = base_result();
        result.code = Some("ARC_AUTH_FORGED".to_string()); // -> security class
        let ctx = || DenialContext { session_id: "s".into(), run_id: "r".into(), task_id: "t".into(), ..Default::default() };
        apply_denial_circuit(result.clone(), Some(&mut circuit), ctx()).unwrap();
        let r2 = apply_denial_circuit(result, Some(&mut circuit), ctx()).unwrap();
        assert!(!r2.termination_terminate);
    }
}
