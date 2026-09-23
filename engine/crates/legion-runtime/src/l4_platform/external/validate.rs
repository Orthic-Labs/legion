//! Port of `src/lib/platform/external/validate.mjs`.
//!
//! Node's original uses `node:crypto`'s generic `verify(null, content, key,
//! signature)`, which auto-detects the key algorithm (RSA/EC/Ed25519) from a
//! PEM public key. `legion-runtime` carries no general asymmetric-crypto
//! dependency, so signature verification here is pluggable: callers pass a
//! [`SignatureVerifier`] closure that performs the actual cryptographic
//! check. When no verifier is supplied, verification fails closed with the
//! `signature-verification-unavailable` gap rather than silently accepting
//! the evidence — this is a deliberate deviation to keep the port free of a
//! new crypto dependency; wire a real verifier before using this in a path
//! that must accept trusted evidence.

use super::super::artifact_sanitize::{is_canonical_base64, sanitize_artifact_content};
use super::super::base64util;
use super::super::contracts::sha256;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// `canonical(value)`: recursively sorts object keys so two structurally
/// equal values serialize identically regardless of key order.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                out.insert(key.clone(), canonical(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn equal(left: &Value, right: &Value) -> bool {
    serde_json::to_string(&canonical(left)).unwrap_or_default()
        == serde_json::to_string(&canonical(right)).unwrap_or_default()
}

/// `utc(value)`: parses an RFC 3339 / ISO-8601 UTC ("...Z") timestamp into
/// milliseconds since epoch, `None` if invalid.
fn utc(value: Option<&str>) -> Option<i64> {
    let value = value?;
    if !value.ends_with('Z') {
        return None;
    }
    // Minimal RFC3339 parse without a datetime crate: rely on chrono-free
    // manual parsing of the fixed `YYYY-MM-DDTHH:MM:SS(.sss)?Z` shape.
    parse_iso8601_utc_millis(value)
}

fn parse_iso8601_utc_millis(s: &str) -> Option<i64> {
    let body = s.strip_suffix('Z')?;
    let (date, time) = body.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let (time_main, frac_millis) = match time.split_once('.') {
        Some((main, frac)) => {
            let mut digits: String = frac.chars().take(3).collect();
            while digits.len() < 3 {
                digits.push('0');
            }
            (main, digits.parse::<i64>().ok()?)
        }
        None => (time, 0),
    };
    let mut time_parts = time_main.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() {
        return None;
    }
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let millis = days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1_000 + frac_millis;
    Some(millis)
}

/// Days since Unix epoch (1970-01-01) for a proleptic Gregorian date, via
/// Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    Some(era * 146097 + doe - 719468)
}

/// `safePath(value)`: rejects absolute paths, drive letters, backslashes,
/// and `.`/`..` segments.
fn safe_path(value: &str) -> bool {
    if value.is_empty() || value.contains('\\') || value.starts_with('/') {
        return false;
    }
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return false;
        }
    }
    let segments: Vec<&str> = value.split('/').collect();
    if segments.len() <= 1 {
        return false;
    }
    let seg_ok = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.chars().enumerate().all(|(i, c)| {
                if i == 0 {
                    c.is_ascii_alphanumeric()
                } else {
                    c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'
                }
            })
    };
    segments.iter().all(|s| seg_ok(s)) && segments.join("/") == value
}

fn artifact_valid(artifact: &Value, binding: &Value) -> bool {
    let obj = match artifact.as_object() {
        Some(obj) => obj,
        None => return false,
    };
    let path_ok = obj.get("path").and_then(Value::as_str).map(safe_path).unwrap_or(false);
    if !path_ok {
        return false;
    }
    let art_binding = obj.get("binding").cloned().unwrap_or(Value::Null);
    if !equal(&art_binding, binding) {
        return false;
    }
    super::super::artifact_sanitize::sanitize_produced_artifact(artifact, &[]).valid
}

/// Optional pluggable signature verifier: `(signed_content, public_key,
/// signature) -> bool`. See module docs.
pub type SignatureVerifier<'a> = dyn Fn(&[u8], &str, &[u8]) -> bool + 'a;

pub struct ExpectedEvidence<'a> {
    pub trusted_producers: Vec<Value>, // [{id, publicKey}]
    pub target_id: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub artifact_digest: Option<&'a str>,
    pub control_id: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub binding: Option<Value>,
    pub now: Option<&'a str>,
    pub max_age_ms: Option<f64>,
    pub sensitive_fields: Vec<Value>,
    pub requires_exercise: bool,
    pub verifier: Option<&'a SignatureVerifier<'a>>,
}

impl<'a> Default for ExpectedEvidence<'a> {
    fn default() -> Self {
        ExpectedEvidence {
            trusted_producers: vec![],
            target_id: None,
            environment: None,
            artifact_digest: None,
            control_id: None,
            scope: None,
            binding: None,
            now: None,
            max_age_ms: None,
            sensitive_fields: vec![],
            requires_exercise: false,
            verifier: None,
        }
    }
}

/// `validateExternalEvidence(evidence, expected)`.
pub fn validate_external_evidence(evidence: Option<&Value>, expected: &ExpectedEvidence) -> Value {
    let mut gaps: Vec<String> = Vec::new();
    let null = Value::Null;
    let ev = evidence.unwrap_or(&null);

    for key in [
        "producer", "scope", "targetId", "environment", "artifactDigest", "controlId", "binding",
        "issuedAt", "checkedAt", "expiresAt",
    ] {
        let present = ev.get(key).map(|v| !v.is_null()).unwrap_or(false)
            && ev.get(key) != Some(&Value::String(String::new()));
        if !present {
            gaps.push(format!("missing-{key}"));
        }
    }

    let producer = ev.get("producer").and_then(Value::as_str);
    let trusted = expected
        .trusted_producers
        .iter()
        .find(|item| item.get("id").and_then(Value::as_str) == producer);
    if trusted.is_none() {
        gaps.push("producer-untrusted".to_string());
    }

    let mut payload: Option<Value> = None;
    let signed_content = ev.get("signedContent").and_then(Value::as_str);
    let signature = ev.get("signature").and_then(Value::as_str);
    if signed_content.is_none() || signature.is_none() {
        gaps.push("signature-unproven".to_string());
    } else if !is_canonical_base64(signature.unwrap()) {
        gaps.push("signature-noncanonical".to_string());
    } else if let Some(trusted) = trusted {
        let public_key = trusted.get("publicKey").and_then(Value::as_str).unwrap_or("");
        let sig_bytes = base64util::decode(signature.unwrap()).unwrap_or_default();
        let verified = match expected.verifier {
            Some(verify) => verify(signed_content.unwrap().as_bytes(), public_key, &sig_bytes),
            None => {
                gaps.push("signature-verification-unavailable".to_string());
                false
            }
        };
        if !verified {
            if expected.verifier.is_some() {
                gaps.push("signature-invalid".to_string());
            }
        } else {
            match serde_json::from_str::<Value>(signed_content.unwrap()) {
                Ok(parsed) => payload = Some(parsed),
                Err(_) => gaps.push("signature-invalid".to_string()),
            }
        }
    }

    let payload_get = |key: &str| -> Option<Value> { payload.as_ref().and_then(|p| p.get(key)).cloned() };

    for key in ["targetId", "environment", "artifactDigest", "controlId"] {
        let expected_value: Option<&str> = match key {
            "targetId" => expected.target_id,
            "environment" => expected.environment,
            "artifactDigest" => expected.artifact_digest,
            "controlId" => expected.control_id,
            _ => None,
        };
        if let Some(exp) = expected_value {
            let payload_value = payload_get(key);
            if payload_value.as_ref().and_then(Value::as_str) != Some(exp) {
                gaps.push(format!("mismatched-{key}"));
            }
        }
        if payload.is_some() {
            let ev_value = ev.get(key).cloned().unwrap_or(Value::Null);
            let payload_value = payload_get(key).unwrap_or(Value::Null);
            if ev_value != payload_value {
                gaps.push(format!("envelope-{key}-mismatch"));
            }
        }
    }

    if let Some(scope) = expected.scope {
        if payload_get("scope").as_ref().and_then(Value::as_str) != Some(scope) {
            gaps.push("mismatched-scope".to_string());
        }
    }
    if payload_get("producer").as_ref().and_then(Value::as_str) != producer {
        gaps.push("mismatched-producer".to_string());
    }
    if payload.is_some() {
        let payload_scope = payload_get("scope").unwrap_or(Value::Null);
        let ev_scope = ev.get("scope").cloned().unwrap_or(Value::Null);
        if payload_scope != ev_scope {
            gaps.push("envelope-scope-mismatch".to_string());
        }
    }
    if let Some(binding) = &expected.binding {
        let payload_binding = payload_get("binding").unwrap_or(Value::Null);
        if !equal(&payload_binding, binding) {
            gaps.push("mismatched-binding".to_string());
        }
    }
    if payload.is_some() {
        let ev_binding = ev.get("binding").cloned().unwrap_or(Value::Null);
        let payload_binding = payload_get("binding").unwrap_or(Value::Null);
        if !equal(&ev_binding, &payload_binding) {
            gaps.push("envelope-binding-mismatch".to_string());
        }
    }
    for key in ["issuedAt", "checkedAt", "expiresAt"] {
        if payload.is_some() {
            let ev_value = ev.get(key).cloned().unwrap_or(Value::Null);
            let payload_value = payload_get(key).unwrap_or(Value::Null);
            if ev_value != payload_value {
                gaps.push(format!("envelope-{key}-mismatch"));
            }
        }
    }

    let issued_at = utc(payload_get("issuedAt").as_ref().and_then(Value::as_str));
    let checked_at = utc(payload_get("checkedAt").as_ref().and_then(Value::as_str));
    let expires_at = utc(payload_get("expiresAt").as_ref().and_then(Value::as_str));
    let now = utc(expected.now);
    if issued_at.is_none() {
        gaps.push("issuedAt-invalid".to_string());
    }
    if checked_at.is_none() {
        gaps.push("checkedAt-invalid".to_string());
    }
    if expires_at.is_none() {
        gaps.push("expiresAt-invalid".to_string());
    }
    if now.is_none() {
        gaps.push("clock-invalid".to_string());
    }
    let max_age_ms = expected.max_age_ms;
    if max_age_ms.map(|v| !v.is_finite() || v < 0.0).unwrap_or(true) {
        gaps.push("max-age-invalid".to_string());
    }
    if let (Some(issued_at), Some(checked_at), Some(expires_at), Some(now)) =
        (issued_at, checked_at, expires_at, now)
    {
        if !(issued_at <= checked_at && checked_at <= now && now <= expires_at) {
            gaps.push("timestamp-order-invalid".to_string());
        }
        if now > expires_at {
            gaps.push("evidence-expired".to_string());
        }
        if let Some(max_age_ms) = max_age_ms {
            if max_age_ms.is_finite() && (now - checked_at) as f64 > max_age_ms {
                gaps.push("evidence-stale".to_string());
            }
        }
    }

    let artifacts = payload_get("artifacts").unwrap_or(Value::Array(vec![]));
    let artifacts_arr = artifacts.as_array().cloned().unwrap_or_default();
    let payload_binding = payload_get("binding").unwrap_or(Value::Null);
    let artifacts_valid = !artifacts_arr.is_empty()
        && artifacts_arr.iter().all(|a| artifact_valid(a, &payload_binding));
    if artifacts.as_array().is_none() || !artifacts_valid {
        gaps.push("produced-artifact-invalid".to_string());
    }
    let sensitized: Vec<_> = artifacts_arr
        .iter()
        .map(|artifact| {
            let fields = artifact.get("sensitiveFields").and_then(Value::as_array).cloned().unwrap_or_else(|| expected.sensitive_fields.clone());
            sanitize_artifact_content(artifact, &fields)
        })
        .collect();
    if sensitized.iter().any(|item| item.sensitive) {
        gaps.push("produced-artifact-sensitive-data".to_string());
    }

    if expected.requires_exercise {
        let exercise = payload_get("exerciseReceipt");
        let terminal_ok = exercise.as_ref().and_then(|e| e.get("terminal")).and_then(Value::as_bool) == Some(true);
        let status_ok = exercise.as_ref().and_then(|e| e.get("status")).and_then(Value::as_str) == Some("pass");
        let exercise_control_id = exercise.as_ref().and_then(|e| e.get("controlId")).and_then(Value::as_str);
        let control_ok = exercise_control_id == expected.control_id;
        let exercise_binding = exercise.as_ref().and_then(|e| e.get("binding")).cloned().unwrap_or(Value::Null);
        let expected_binding = expected.binding.clone().unwrap_or(Value::Null);
        let binding_ok = equal(&exercise_binding, &expected_binding);
        if !terminal_ok || !status_ok || !control_ok || !binding_ok {
            gaps.push("exercise-required".to_string());
        }
        let ev_exercise = ev.get("exerciseReceipt").cloned().unwrap_or(Value::Null);
        let payload_exercise = exercise.unwrap_or(Value::Null);
        if !equal(&ev_exercise, &payload_exercise) {
            gaps.push("envelope-exercise-mismatch".to_string());
        }
    }

    let safe_payload = match (&payload, artifacts.as_array()) {
        (Some(p), Some(_)) => {
            let mut obj = p.as_object().cloned().unwrap_or_default();
            obj.insert(
                "artifacts".to_string(),
                Value::Array(sensitized.iter().map(|item| item.artifact.clone().unwrap_or(Value::Null)).collect()),
            );
            Some(Value::Object(obj))
        }
        _ => payload.clone(),
    };

    let unique_sorted: Vec<Value> = {
        let set: BTreeSet<String> = gaps.into_iter().collect();
        set.into_iter().map(Value::String).collect()
    };

    json!({
        "schemaVersion": 1,
        "kind": "legion-external-evidence-validation",
        "evidenceDigest": evidence.map(sha256),
        "status": if unique_sorted.is_empty() { "pass" } else { "unproven" },
        "payload": safe_payload,
        "gaps": unique_sorted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_evidence_reports_gaps() {
        let result = validate_external_evidence(None, &ExpectedEvidence::default());
        assert_eq!(result["status"], "unproven");
        let gaps = result["gaps"].as_array().unwrap();
        assert!(gaps.iter().any(|g| g == "missing-producer"));
        assert!(gaps.iter().any(|g| g == "producer-untrusted"));
    }

    #[test]
    fn safe_path_rejects_traversal_and_absolute() {
        assert!(!safe_path("../etc/passwd"));
        assert!(!safe_path("/etc/passwd"));
        assert!(!safe_path("C:/windows"));
        assert!(safe_path("dist/pkg.tgz"));
    }

    #[test]
    fn utc_parses_iso8601() {
        assert_eq!(utc(Some("1970-01-01T00:00:00Z")), Some(0));
        assert_eq!(utc(Some("1970-01-01T00:00:01Z")), Some(1000));
        assert!(utc(Some("not-a-date")).is_none());
    }
}
