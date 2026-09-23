//! Port of `src/providers/runtime/web/infrastructure/index.mjs`
//! (`verifyInfrastructureExercise`).
//!
//! Signature verification is behind [`SignatureVerifier`] because this crate
//! has no Ed25519/asymmetric-crypto dependency wired yet (the JS calls
//! `node:crypto`'s `verify(null, ...)`, which only accepts Ed25519/Ed448
//! keys). See the wf049 report for the `Cargo.toml` patch needed to back
//! [`RealSignatureVerifier`] with real crypto (e.g. `ring`); until that
//! lands this file is PORTED-PARTIAL: all gap logic is faithfully ported,
//! but no supplied evidence can ever pass real signature verification.

use serde_json::{Map, Value};

use super::shared::{
    canonicalize, exact_binding, is_canonical_base64, safe_path, same_binding, sanitize_artifact_content,
    sanitize_sensitive_value, utc_millis,
};

/// Verifies a detached signature over `signed_content` using `public_key`,
/// mirroring `crypto.verify(null, Buffer.from(signedContent), producer.publicKey, Buffer.from(signature, 'base64'))`.
pub trait SignatureVerifier {
    fn verify(&self, public_key: &str, signed_content: &[u8], signature: &[u8]) -> bool;
}

/// No crypto dependency is wired into `legion-audit` yet; this verifier
/// always reports the signature as invalid so callers see `signature-invalid`
/// (a safe failure mode: production evidence is rejected, never wrongly
/// accepted) rather than silently trusting unverified evidence.
pub struct UnimplementedSignatureVerifier;

impl SignatureVerifier for UnimplementedSignatureVerifier {
    fn verify(&self, _public_key: &str, _signed_content: &[u8], _signature: &[u8]) -> bool {
        false
    }
}

const REQUIRED_CONTROLS: &[&str] = &[
    "cdn", "deployment", "dns", "drift", "health", "iam", "infra", "network", "region", "rollback", "runtime",
    "scaling", "secrets", "storage", "tls",
];

fn valid_artifact(artifact: &Value, binding: &Value) -> bool {
    let Some(obj) = artifact.as_object() else { return false };
    if !safe_path(&artifact["path"]) {
        return false;
    }
    if !same_binding(binding, obj.get("binding").unwrap_or(&Value::Null)) {
        return false;
    }
    let (_, sensitive, _) = sanitize_artifact_content(artifact, &Value::Null);
    if sensitive {
        return false;
    }
    let has_content = artifact.get("content").and_then(Value::as_str).is_some();
    let has_bytes = artifact.get("bytesBase64").and_then(Value::as_str).is_some();
    if has_content == has_bytes {
        return false;
    }
    let bytes: Option<Vec<u8>> = if has_content {
        Some(artifact.get("content").and_then(Value::as_str).unwrap().as_bytes().to_vec())
    } else {
        let b64 = artifact.get("bytesBase64").and_then(Value::as_str).unwrap();
        if is_canonical_base64(b64) {
            super::shared::base64_decode(b64)
        } else {
            None
        }
    };
    let Some(bytes) = bytes else { return false };
    if bytes.is_empty() {
        return false;
    }
    let expected = format!("sha256:{}", sha256_hex(&bytes));
    artifact.get("digest").and_then(Value::as_str) == Some(expected.as_str())
}

fn typed_fact(fact: &Value) -> bool {
    if fact.as_object().is_none() {
        return false;
    }
    matches!(fact.get("id"), Some(Value::String(id)) if !id.is_empty()) && matches!(fact.get("kind"), Some(Value::String(_)))
}

fn infrastructure_fact_gaps(payload: &Value, binding: &Value) -> Vec<String> {
    let mut gaps = Vec::new();
    let denominator: Vec<String> = payload
        .get("applicableControls")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let mut sorted_unique: Vec<String> = denominator.clone();
    sorted_unique.sort();
    sorted_unique.dedup();
    let mut required_sorted: Vec<String> = REQUIRED_CONTROLS.iter().map(|s| s.to_string()).collect();
    required_sorted.sort();
    if sorted_unique != required_sorted {
        gaps.push("infrastructure-control-denominator-mismatch".to_string());
    }
    let facts_array = payload.get("controlFacts").and_then(Value::as_array);
    let facts_valid = facts_array.map(|items| items.iter().all(typed_fact)).unwrap_or(false);
    if !facts_valid {
        gaps.push("infrastructure-control-facts-invalid".to_string());
    }
    let empty: Vec<Value> = Vec::new();
    let facts: &Vec<Value> = if facts_valid { facts_array.unwrap() } else { &empty };
    for id in REQUIRED_CONTROLS {
        let matches: Vec<&Value> = facts.iter().filter(|f| f.get("id").and_then(Value::as_str) == Some(*id)).collect();
        if matches.is_empty() {
            gaps.push(format!("infrastructure-control-missing:{id}"));
            continue;
        }
        if matches.len() > 1 {
            gaps.push(format!("infrastructure-control-duplicate:{id}"));
        }
        let fact = matches[0];
        if fact.get("kind").and_then(Value::as_str) != Some("infrastructure-control-fact")
            || fact.get("applicable") != Some(&Value::Bool(true))
        {
            gaps.push(format!("infrastructure-control-type-invalid:{id}"));
        }
        if fact.get("configured") != Some(&Value::Bool(true)) {
            gaps.push(format!("infrastructure-control-not-configured:{id}"));
        }
        if fact.get("deployed") != Some(&Value::Bool(true)) {
            gaps.push(format!("infrastructure-control-not-deployed:{id}"));
        }
        if fact.get("exercised") != Some(&Value::Bool(true))
            || fact.get("status").and_then(Value::as_str) != Some("pass")
            || fact.get("terminal") != Some(&Value::Bool(true))
        {
            gaps.push(format!("infrastructure-control-not-exercised:{id}"));
        }
        if !same_binding(binding, fact.get("binding").unwrap_or(&Value::Null)) {
            gaps.push(format!("infrastructure-control-binding-mismatch:{id}"));
        }
        let artifacts = fact.get("artifacts").and_then(Value::as_array);
        let ok = artifacts
            .map(|items| !items.is_empty() && items.iter().all(|a| valid_artifact(a, binding)))
            .unwrap_or(false);
        if !ok {
            gaps.push(format!("infrastructure-control-artifact-invalid:{id}"));
        }
    }
    for fact in facts {
        let id = fact.get("id").and_then(Value::as_str).unwrap_or("missing");
        if !REQUIRED_CONTROLS.contains(&id) {
            gaps.push(format!("infrastructure-control-unplanned:{id}"));
        }
    }
    gaps
}

pub struct VerifyInfrastructureExerciseInput<'a> {
    pub binding: Value,
    pub evidence: Option<Value>,
    pub trusted_producers: Vec<Value>,
    pub now: Option<String>,
    pub max_age_ms: Option<f64>,
    pub signature_verifier: &'a dyn SignatureVerifier,
}

impl<'a> Default for VerifyInfrastructureExerciseInput<'a> {
    fn default() -> Self {
        Self {
            binding: Value::Object(Map::new()),
            evidence: None,
            trusted_producers: Vec::new(),
            now: None,
            max_age_ms: None,
            signature_verifier: &UNIMPLEMENTED_VERIFIER,
        }
    }
}

static UNIMPLEMENTED_VERIFIER: UnimplementedSignatureVerifier = UnimplementedSignatureVerifier;

/// Port of `verifyInfrastructureExercise` in `infrastructure/index.mjs`.
pub fn verify_infrastructure_exercise(input: VerifyInfrastructureExerciseInput<'_>) -> Value {
    let VerifyInfrastructureExerciseInput {
        binding,
        evidence,
        trusted_producers,
        now,
        max_age_ms,
        signature_verifier,
    } = input;

    let producers_valid = trusted_producers.iter().all(|item| {
        item.as_object().is_some()
            && matches!(item.get("id"), Some(Value::String(id)) if !id.is_empty())
            && item.get("publicKey").is_some()
    });
    let producer_field = evidence.as_ref().and_then(|e| e.get("producer")).cloned().unwrap_or(Value::Null);

    if !producers_valid {
        let mut gaps: Vec<String> = exact_binding(&binding).gaps.iter().map(|g| format!("binding-missing:{g}")).collect();
        gaps.push("trusted-producers-invalid".to_string());
        gaps.sort();
        gaps.dedup();
        return super::shared::finalize(
            "legion-web-infrastructure-exercise",
            serde_json::json!({
                "status": "error",
                "terminal": true,
                "claimLevel": "external",
                "suppliedOnly": true,
                "networkAttempted": false,
                "binding": binding,
                "producer": producer_field,
                "payload": Value::Null,
                "evidenceDigest": Value::Null,
                "coverageGaps": gaps,
            }),
        );
    }

    let mut gaps: Vec<String> = exact_binding(&binding).gaps.iter().map(|g| format!("binding-missing:{g}")).collect();
    let mut payload: Option<Value> = None;

    let producer = trusted_producers
        .iter()
        .find(|item| item.get("id") == Some(&producer_field));

    if evidence.is_none() {
        gaps.push("supplied-evidence-missing".to_string());
    }
    if producer.is_none() {
        gaps.push("producer-untrusted".to_string());
    }

    let signed_content = evidence.as_ref().and_then(|e| e.get("signedContent")).and_then(Value::as_str);
    let signature = evidence.as_ref().and_then(|e| e.get("signature")).and_then(Value::as_str);

    if signed_content.is_none() || signature.is_none() {
        gaps.push("signature-unproven".to_string());
    } else if !is_canonical_base64(signature.unwrap()) {
        gaps.push("signature-noncanonical".to_string());
    } else if let Some(producer) = producer {
        let public_key = producer.get("publicKey").and_then(Value::as_str).unwrap_or_default();
        let sig_bytes = super::shared::base64_decode(signature.unwrap()).unwrap_or_default();
        let content = signed_content.unwrap();
        if !signature_verifier.verify(public_key, content.as_bytes(), &sig_bytes) {
            gaps.push("signature-invalid".to_string());
        } else {
            match serde_json::from_str::<Value>(content) {
                Ok(parsed) => payload = Some(parsed),
                Err(_) => gaps.push("signature-invalid".to_string()),
            }
        }
    }

    let evidence_digest = signed_content.map(|content| format!("sha256:{}", sha256_hex(content.as_bytes())));

    if payload.is_none() {
        gaps.push("deployed-proof-required".to_string());
        gaps.push("rollback-not-exercised".to_string());
    } else {
        let payload_val = payload.as_ref().unwrap().clone();
        if payload_val.get("producer") != Some(&producer_field) {
            gaps.push("producer-mismatch".to_string());
        }
        for key in ["targetId", "environment", "artifactDigest"] {
            if payload_val.get(key) != binding.get(key) {
                gaps.push(format!("{key}-mismatch"));
            }
        }
        if !same_binding(&binding, payload_val.get("binding").unwrap_or(&Value::Null)) {
            gaps.push("binding-mismatch".to_string());
        }
        let issued = utc_millis(payload_val.get("issuedAt").and_then(Value::as_str));
        let checked = utc_millis(payload_val.get("checkedAt").and_then(Value::as_str));
        let current = utc_millis(now.as_deref());
        let expires = utc_millis(payload_val.get("expiresAt").and_then(Value::as_str));
        for (key, value) in [("issuedAt", issued), ("checkedAt", checked), ("now", current), ("expiresAt", expires)] {
            if value.is_none() {
                gaps.push(format!("{key}-timestamp-invalid"));
            }
        }
        let max_age_valid = max_age_ms.map(|v| v.is_finite() && v >= 0.0).unwrap_or(false);
        if !max_age_valid {
            gaps.push("freshness-window-invalid".to_string());
        }
        if let (Some(issued), Some(checked)) = (issued, checked) {
            if issued > checked {
                gaps.push("issued-after-checked".to_string());
            }
        }
        if let (Some(checked), Some(current)) = (checked, current) {
            if checked > current {
                gaps.push("checked-in-future".to_string());
            }
        }
        if let (Some(checked), Some(expires)) = (checked, expires) {
            if checked > expires {
                gaps.push("checked-after-expiry".to_string());
            }
        }
        if let (Some(current), Some(expires)) = (current, expires) {
            if current > expires {
                gaps.push("evidence-expired".to_string());
            }
        }
        if let (Some(checked), Some(current), Some(max_age_ms)) = (checked, current, max_age_ms) {
            if max_age_valid && (current - checked) as f64 > max_age_ms {
                gaps.push("evidence-stale".to_string());
            }
        }
        let receipt = payload_val.get("exerciseReceipt");
        if receipt.and_then(|r| r.get("terminal")) != Some(&Value::Bool(true))
            || receipt.and_then(|r| r.get("status")).and_then(Value::as_str) != Some("pass")
        {
            gaps.push("exercise-receipt-unproven".to_string());
        }
        let receipt_artifacts = receipt.and_then(|r| r.get("artifacts")).and_then(Value::as_array);
        let artifacts_valid = receipt_artifacts
            .map(|items| !items.is_empty() && items.iter().all(|a| a.is_object()))
            .unwrap_or(false);
        if !artifacts_valid {
            gaps.push("exercise-receipt-artifacts-invalid".to_string());
        }
        let empty: Vec<Value> = Vec::new();
        let artifacts: &Vec<Value> = if artifacts_valid { receipt_artifacts.unwrap() } else { &empty };
        let all_valid = !artifacts.is_empty() && artifacts.iter().all(|a| valid_artifact(a, &binding));
        if !all_valid {
            gaps.push("produced-evidence-invalid".to_string());
        }
        gaps.extend(infrastructure_fact_gaps(&payload_val, &binding));

        let (sanitized_value, sensitive) = sanitize_sensitive_value(&payload_val, &Value::Null);
        let sanitize_artifacts = |values: Option<&Vec<Value>>| -> Value {
            match values {
                Some(items) => Value::Array(
                    items
                        .iter()
                        .map(|artifact| sanitize_artifact_content(artifact, &Value::Null).0.unwrap_or(Value::Null))
                        .collect(),
                ),
                None => Value::Null,
            }
        };
        let control_facts_array = payload_val.get("controlFacts").and_then(Value::as_array);
        let control_facts_valid = control_facts_array.map(|items| items.iter().all(typed_fact)).unwrap_or(false);
        let safe_control_facts: Value = if control_facts_valid {
            let sanitized_facts = sanitized_value.get("controlFacts").and_then(Value::as_array).cloned().unwrap_or_default();
            Value::Array(
                control_facts_array
                    .unwrap()
                    .iter()
                    .map(|fact| {
                        let id = fact.get("id").and_then(Value::as_str);
                        let mut base = sanitized_facts
                            .iter()
                            .find(|item| item.get("id").and_then(Value::as_str) == id)
                            .cloned()
                            .unwrap_or(Value::Null);
                        if let Value::Object(map) = &mut base {
                            map.insert(
                                "artifacts".to_string(),
                                sanitize_artifacts(fact.get("artifacts").and_then(Value::as_array)),
                            );
                        }
                        base
                    })
                    .collect(),
            )
        } else {
            Value::Array(Vec::new())
        };

        let exercise_receipt = if payload_val.get("exerciseReceipt").is_some() {
            let mut base = sanitized_value.get("exerciseReceipt").cloned().unwrap_or(Value::Null);
            if let Value::Object(map) = &mut base {
                map.insert(
                    "artifacts".to_string(),
                    sanitize_artifacts(
                        payload_val
                            .get("exerciseReceipt")
                            .and_then(|r| r.get("artifacts"))
                            .and_then(Value::as_array),
                    ),
                );
            }
            base
        } else {
            sanitized_value.get("exerciseReceipt").cloned().unwrap_or(Value::Null)
        };

        let mut final_payload = sanitized_value.as_object().cloned().unwrap_or_default();
        final_payload.insert("controlFacts".to_string(), safe_control_facts);
        final_payload.insert("exerciseReceipt".to_string(), exercise_receipt);
        payload = Some(Value::Object(final_payload));

        if sensitive {
            gaps.push("infrastructure-sensitive-data".to_string());
        }
    }

    gaps.sort();
    gaps.dedup();
    let status = if gaps.is_empty() { "pass" } else { "unproven" };

    super::shared::finalize(
        "legion-web-infrastructure-exercise",
        serde_json::json!({
            "status": status,
            "terminal": true,
            "claimLevel": "external",
            "suppliedOnly": true,
            "networkAttempted": false,
            "binding": binding,
            "producer": producer_field,
            "payload": payload,
            "evidenceDigest": evidence_digest,
            "coverageGaps": gaps,
        }),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}
