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
//! ## Packet r50: the `DenialCircuit` class
//! The JS `DenialCircuit` class persists HMAC-authenticated receipts to disk
//! (`node:fs`, `node:crypto`) using the shared `signRecord`/`verifyRecord`
//! machinery from `src/lib/guard/compat/audit/receipt-auth.mjs`. That
//! machinery is now ported in `super::receipt_auth` (also added in packet
//! r50), and [`FileDenialCircuit`] below is the byte-faithful `DenialRecorder`
//! built on it: same `recordPath` scheme (sha256 hex of the canonical scope,
//! no `sha256:` prefix, matching `createHash('sha256')` directly rather than
//! `digestValue`), same `DENIAL_CIRCUIT_BOUND_FIELDS`/`DOMAIN`, same
//! read-verify-count-sign-write(tmp+rename) sequence, same error taxonomy
//! (`ARC_AUTH_KEY_UNAVAILABLE`, `ARC_STORE_CORRUPT`, and any
//! `verify_record` denial code, non-fatal parse of a corrupt prior record
//! folded into `ARC_STORE_CORRUPT` exactly as the JS `catch` block does).

use super::canonical::{canonical_json, digest_value, sha256_hex};
use super::receipt_auth::{sign_record, verify_record, KeyRing};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

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

pub const DENIAL_CIRCUIT_BOUND_FIELDS: &[&str] = &[
    "schemaVersion",
    "kind",
    "sessionId",
    "runId",
    "taskId",
    "controlClass",
    "code",
    "missingEvidenceDigest",
    "targetDigest",
    "fingerprint",
    "count",
    "issuedAt",
];

const DOMAIN: &str = "arcane-denial-circuit:v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialCircuitError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for DenialCircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for DenialCircuitError {}

fn record_path(root: &Path, session_id: &str, run_id: &str, task_id: &str) -> PathBuf {
    let scope = json!({ "sessionId": session_id, "runId": run_id, "taskId": task_id });
    root.join(format!("{}.json", sha256_hex(&canonical_json(&scope))))
}

/// Port of `DenialCircuit`: an authenticated, disk-persisted `DenialRecorder`.
/// `clock` mirrors the JS constructor's `clock = () => new Date().toISOString()`
/// default — callers inject it for deterministic tests.
pub struct FileDenialCircuit<'a> {
    root: PathBuf,
    key_ring: &'a dyn KeyRing,
    key_id: String,
    clock: Box<dyn FnMut() -> String + 'a>,
}

impl<'a> FileDenialCircuit<'a> {
    pub fn new(
        root: PathBuf,
        key_ring: &'a dyn KeyRing,
        key_id: &str,
        clock: Box<dyn FnMut() -> String + 'a>,
    ) -> Result<Self, DenialCircuitError> {
        if key_id.is_empty() {
            return Err(DenialCircuitError {
                code: "ARC_AUTH_KEY_UNAVAILABLE",
                message: "authenticated denial circuit requires root and active key".to_string(),
            });
        }
        Ok(Self { root, key_ring, key_id: key_id.to_string(), clock })
    }
}

impl<'a> DenialRecorder for FileDenialCircuit<'a> {
    type Error = DenialCircuitError;

    fn record(&mut self, record: DenialRecord) -> Result<RecordOutcome, Self::Error> {
        if record.session_id.is_empty() || record.run_id.is_empty() || record.task_id.is_empty() {
            return Err(DenialCircuitError { code: "ARC_SCHEMA_INVALID", message: "denial circuit requires sessionId/runId/taskId".to_string() });
        }
        if record.control_class.is_empty() || record.code.is_empty() {
            return Err(DenialCircuitError { code: "ARC_SCHEMA_INVALID", message: "denial circuit requires controlClass/code".to_string() });
        }
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
        let path = record_path(&self.root, &record.session_id, &record.run_id, &record.task_id);

        let run_body = || -> Result<RecordOutcome, DenialCircuitError> {
            let prior: Option<Value> = if path.exists() {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| DenialCircuitError { code: "ARC_STORE_CORRUPT", message: e.to_string() })?;
                let parsed: Value = serde_json::from_str(&text)
                    .map_err(|e| DenialCircuitError { code: "ARC_STORE_CORRUPT", message: e.to_string() })?;
                let auth = parsed.get("authentication").cloned().unwrap_or(Value::Null);
                let expected_binding = [
                    ("sessionId", record.session_id.as_str()),
                    ("runId", record.run_id.as_str()),
                    ("taskId", record.task_id.as_str()),
                ];
                verify_record(&parsed, &auth, self.key_ring, DENIAL_CIRCUIT_BOUND_FIELDS, &expected_binding, Some(DOMAIN)).map_err(|d| {
                    DenialCircuitError { code: d.code, message: d.message }
                })?;
                Some(parsed)
            } else {
                None
            };

            let count = match &prior {
                Some(p) if p.get("fingerprint").and_then(Value::as_str) == Some(fingerprint.as_str()) => {
                    let prior_count = p.get("count").and_then(Value::as_u64).unwrap_or(0) as u32;
                    (prior_count + 1).min(MAX_IDENTICAL_DENIALS)
                }
                _ => 1,
            };

            let issued_at = (self.clock)();
            let mut receipt = json!({
                "schemaVersion": 1,
                "kind": "arcane-denial-circuit-receipt",
                "sessionId": record.session_id,
                "runId": record.run_id,
                "taskId": record.task_id,
                "controlClass": record.control_class,
                "code": record.code,
                "missingEvidenceDigest": missing_evidence_digest,
                "targetDigest": target_digest,
                "fingerprint": fingerprint,
                "count": count,
                "issuedAt": issued_at,
            });
            let signed = sign_record(&receipt, self.key_ring, &self.key_id, DENIAL_CIRCUIT_BOUND_FIELDS, Some(DOMAIN))
                .map_err(|e| DenialCircuitError { code: "ARC_AUTH_KEY_UNAVAILABLE", message: e.0 })?;
            receipt["authentication"] = signed.to_json();

            std::fs::create_dir_all(&self.root).map_err(|e| DenialCircuitError { code: "ARC_STORE_CORRUPT", message: e.to_string() })?;
            let tmp = self.root.join(format!(".{}.{}.tmp", std::process::id(), fingerprint));
            std::fs::write(&tmp, format!("{}\n", serde_json::to_string(&receipt).unwrap()))
                .map_err(|e| DenialCircuitError { code: "ARC_STORE_CORRUPT", message: e.to_string() })?;
            std::fs::rename(&tmp, &path).map_err(|e| DenialCircuitError { code: "ARC_STORE_CORRUPT", message: e.to_string() })?;

            let opened = count >= MAX_IDENTICAL_DENIALS && !matches!(record.control_class.as_str(), "effect" | "security");
            Ok(RecordOutcome { receipt: DenialReceipt { fingerprint: fingerprint.clone(), count }, opened })
        };
        run_body()
    }
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

    struct FixedKeyRing;
    impl KeyRing for FixedKeyRing {
        fn get(&self, key_id: &str) -> Option<super::super::receipt_auth::KeyRingEntry<'_>> {
            if key_id == "k1" {
                Some(super::super::receipt_auth::KeyRingEntry { key_id: "k1", key: b"denial-circuit-test-key", revoked: false })
            } else {
                None
            }
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("legion-denial-circuit-{}-{}-{n}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn record_for(session: &str) -> DenialRecord {
        DenialRecord {
            session_id: session.to_string(),
            run_id: "r".into(),
            task_id: "t".into(),
            control_class: "evidence".into(),
            code: "ARC_EVIDENCE_STALE".into(),
            missing_evidence: vec!["deterministic".into()],
            target: None,
        }
    }

    #[test]
    fn file_denial_circuit_persists_and_counts() {
        let root = temp_dir("counts");
        let ring = FixedKeyRing;
        let mut clock_calls = 0u32;
        let mut circuit = FileDenialCircuit::new(
            root.clone(),
            &ring,
            "k1",
            Box::new(move || {
                clock_calls += 1;
                format!("2026-01-01T00:00:0{clock_calls}.000Z")
            }),
        )
        .unwrap();

        let r1 = circuit.record(record_for("s1")).unwrap();
        assert_eq!(r1.receipt.count, 1);
        assert!(!r1.opened);

        let r2 = circuit.record(record_for("s1")).unwrap();
        assert_eq!(r2.receipt.count, 2);
        // "evidence" control class is not in {effect, security}, so it opens
        // once the identical denial is seen MAX_IDENTICAL_DENIALS times.
        assert!(r2.opened);
        assert_eq!(r1.receipt.fingerprint, r2.receipt.fingerprint);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn file_denial_circuit_different_fingerprint_resets_count() {
        let root = temp_dir("reset");
        let ring = FixedKeyRing;
        let mut circuit = FileDenialCircuit::new(root.clone(), &ring, "k1", Box::new(|| "2026-01-01T00:00:00.000Z".to_string())).unwrap();

        circuit.record(record_for("s1")).unwrap();
        let mut different = record_for("s1");
        different.code = "ARC_EVIDENCE_INSUFFICIENT".to_string();
        let r2 = circuit.record(different).unwrap();
        assert_eq!(r2.receipt.count, 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn file_denial_circuit_rejects_missing_key() {
        let root = temp_dir("missing-key");
        let ring = FixedKeyRing;
        let mut circuit = FileDenialCircuit::new(root.clone(), &ring, "no-such-key", Box::new(|| "2026-01-01T00:00:00.000Z".to_string())).unwrap();
        let err = circuit.record(record_for("s1")).unwrap_err();
        assert_eq!(err.code, "ARC_AUTH_KEY_UNAVAILABLE");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn file_denial_circuit_detects_tampered_prior_receipt() {
        let root = temp_dir("tamper");
        let ring = FixedKeyRing;
        {
            let mut circuit = FileDenialCircuit::new(root.clone(), &ring, "k1", Box::new(|| "2026-01-01T00:00:00.000Z".to_string())).unwrap();
            circuit.record(record_for("s1")).unwrap();
        }
        let path = record_path(&root, "s1", "r", "t");
        let mut body: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        body["count"] = json!(999);
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();

        let mut circuit = FileDenialCircuit::new(root.clone(), &ring, "k1", Box::new(|| "2026-01-01T00:00:01.000Z".to_string())).unwrap();
        let err = circuit.record(record_for("s1")).unwrap_err();
        assert_eq!(err.code, "ARC_AUTH_FORGED");

        let _ = std::fs::remove_dir_all(&root);
    }
}
