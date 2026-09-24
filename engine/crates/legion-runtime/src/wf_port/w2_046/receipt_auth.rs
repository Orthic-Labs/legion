//! Port of `src/lib/guard/compat/audit/receipt-auth.mjs` — S03 authenticated
//! receipts: HMAC over an explicit bound-field list.
//!
//! Added in packet r50 to close the `DenialCircuit` gap in `denial_circuit.rs`
//! (the JS `DenialCircuit` class persists HMAC-authenticated receipts using
//! this module's `signRecord`/`verifyRecord`). Only the pieces the denial
//! circuit exercises are ported here: `MAC_ALGORITHM`, `signRecord`,
//! `verifyRecord`, `authenticationBlock`, `connectionTrustBlock`, and the
//! supporting `KeyRing` contract. `EFFECT_RECEIPT_BOUND_FIELDS` /
//! `EVIDENCE_RECEIPT_BOUND_FIELDS` are not ported: no caller in this chunk's
//! files needs them, and adding them speculatively would be unverifiable
//! dead code.

use super::canonical::{canonical_json, constant_time_equal, digest, hmac_sha256_hex, project_bound_fields};
use serde_json::{json, Map, Value};

pub const MAC_ALGORITHM: &str = "HMAC-SHA256";

/// Fields a record may never assert about itself. Mirrors
/// `SELF_ASSERTED_AUTHORITY_FIELDS`.
const SELF_ASSERTED_AUTHORITY_FIELDS: &[&str] =
    &["authority", "callerAuthority", "assertedAuthority", "trust_class", "trustClass"];

/// Bindings the verifier can constrain. Mirrors `BINDING_FIELDS`.
const BINDING_FIELDS: &[&str] =
    &["runId", "taskId", "workspace", "workspaceId", "operation", "sessionId", "contractId"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAuthError(pub String);

impl std::fmt::Display for ReceiptAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ReceiptAuthError {}

/// A signing/verifying key ring. Mirrors the `keyRing.get(keyId)` contract
/// (throws `ARC_AUTH_KEY_UNAVAILABLE` when absent, which this port surfaces
/// as `Err(ReceiptAuthError)` from `sign_record`/`verify_record` since Rust
/// has no analogous "fail closed by throwing" distinct from a `Result`).
pub trait KeyRing {
    /// `None` when the key is absent or revoked-and-unknown; a present key
    /// carries its bytes and whether it has been revoked.
    fn get(&self, key_id: &str) -> Option<KeyRingEntry<'_>>;
}

pub struct KeyRingEntry<'a> {
    pub key_id: &'a str,
    pub key: &'a [u8],
    pub revoked: bool,
}

fn digest_of_bound_field_list(bound_fields: &[&str]) -> String {
    let list = Value::Array(bound_fields.iter().map(|f| Value::String((*f).to_string())).collect());
    digest(&canonical_json(&list))
}

fn mac_over(key: &[u8], record: &Value, bound_fields: &[&str], mac_domain: Option<&str>) -> Result<String, ReceiptAuthError> {
    let projected = project_bound_fields(record, bound_fields).map_err(ReceiptAuthError)?;
    let bound_fields_json = Value::Array(bound_fields.iter().map(|f| Value::String((*f).to_string())).collect());
    let message = match mac_domain {
        None => json!({ "alg": MAC_ALGORITHM, "boundFields": bound_fields_json, "subject": projected }),
        Some(domain) => {
            json!({ "alg": MAC_ALGORITHM, "boundFields": bound_fields_json, "macDomain": domain, "subject": projected })
        }
    };
    let text = canonical_json(&message);
    Ok(hmac_sha256_hex(key, text.as_bytes()))
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedRecord {
    pub alg: String,
    pub key_id: String,
    pub mac: String,
    pub mac_domain: Option<String>,
    pub bound_fields_digest: String,
}

impl SignedRecord {
    /// The JSON shape stored on a record's `authentication` field.
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("alg".to_string(), json!(self.alg));
        map.insert("keyId".to_string(), json!(self.key_id));
        map.insert("mac".to_string(), json!(self.mac));
        if let Some(domain) = &self.mac_domain {
            map.insert("macDomain".to_string(), json!(domain));
        }
        map.insert("boundFieldsDigest".to_string(), json!(self.bound_fields_digest));
        Value::Object(map)
    }
}

/// Port of `signRecord`.
pub fn sign_record(
    record: &Value,
    key_ring: &dyn KeyRing,
    key_id: &str,
    bound_fields: &[&str],
    mac_domain: Option<&str>,
) -> Result<SignedRecord, ReceiptAuthError> {
    if bound_fields.is_empty() {
        return Err(ReceiptAuthError("signRecord requires a non-empty boundFields list".to_string()));
    }
    let entry = key_ring
        .get(key_id)
        .ok_or_else(|| ReceiptAuthError(format!("no key available for keyId: {key_id}")))?;
    Ok(SignedRecord {
        alg: MAC_ALGORITHM.to_string(),
        key_id: entry.key_id.to_string(),
        mac: mac_over(entry.key, record, bound_fields, mac_domain)?,
        mac_domain: mac_domain.map(str::to_string),
        bound_fields_digest: digest_of_bound_field_list(bound_fields),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyDenial {
    pub allowed: bool,
    pub code: &'static str,
    pub message: String,
}

fn denied(code: &'static str, message: impl Into<String>) -> VerifyDenial {
    VerifyDenial { allowed: false, code, message: message.into() }
}

/// Port of `verifyRecord`, narrowed to the fields this chunk's callers use:
/// `record`'s `authentication` block is passed as `auth`, and
/// `expectedBinding` is an explicit list of `(field, expected_value)` pairs
/// rather than an arbitrary object (Rust has no dynamic property bag as
/// convenient as the JS one here).
///
/// Step 1 (`signature_or_mac` legacy self-hash refusal) is intentionally not
/// ported: nothing in this chunk ever constructs or presents a legacy
/// `signature_or_mac` field, so there is no `auth` shape to detect it from
/// at this call boundary — the field simply doesn't exist in
/// `SignedRecord`.
pub fn verify_record(
    record: &Value,
    auth: &Value,
    key_ring: &dyn KeyRing,
    bound_fields: &[&str],
    expected_binding: &[(&str, &str)],
    mac_domain: Option<&str>,
) -> Result<(), VerifyDenial> {
    let auth_obj = match auth.as_object() {
        Some(o) => o,
        None => return Err(denied("ARC_AUTH_UNAUTHENTICATED", "no authentication material present on this record")),
    };
    let mac = auth_obj.get("mac").and_then(Value::as_str);
    let key_id = auth_obj.get("keyId").and_then(Value::as_str);
    let (mac, key_id) = match (mac, key_id) {
        (Some(m), Some(k)) => (m, k),
        _ => return Err(denied("ARC_AUTH_UNAUTHENTICATED", "no authentication material present on this record")),
    };
    let alg = auth_obj.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != MAC_ALGORITHM {
        return Err(denied("ARC_AUTH_FORGED", format!("unsupported MAC algorithm: {alg}")));
    }
    let presented_domain = auth_obj.get("macDomain").and_then(Value::as_str);
    if let Some(expected_domain) = mac_domain {
        if presented_domain != Some(expected_domain) {
            return Err(denied("ARC_AUTH_FORGED", "MAC domain does not match verifier requirement"));
        }
    }

    let expected_fields_digest = digest_of_bound_field_list(bound_fields);
    let presented_fields_digest = auth_obj.get("boundFieldsDigest").and_then(Value::as_str).unwrap_or("");
    if !constant_time_equal(presented_fields_digest.as_bytes(), expected_fields_digest.as_bytes()) {
        return Err(denied(
            "ARC_AUTH_FORGED",
            "signed bound-field list does not match the verifier's required field list",
        ));
    }

    let entry = key_ring
        .get(key_id)
        .ok_or_else(|| ReceiptAuthError(format!("no key available for keyId: {key_id}")))
        .map_err(|e| denied("ARC_AUTH_KEY_UNAVAILABLE", e.0))?;
    if entry.revoked {
        return Err(denied("ARC_CAPABILITY_REVOKED", format!("signing key {key_id} is revoked")));
    }

    let effective_domain = mac_domain.or(presented_domain);
    let expected_mac = mac_over(entry.key, record, bound_fields, effective_domain)
        .map_err(|e| denied("ARC_AUTH_FORGED", format!("record is missing a bound field: {e}")))?;
    if !constant_time_equal(mac.as_bytes(), expected_mac.as_bytes()) {
        return Err(denied("ARC_AUTH_FORGED", "MAC does not verify over the bound fields"));
    }

    if let Some(record_obj) = record.as_object() {
        for field in SELF_ASSERTED_AUTHORITY_FIELDS {
            if record_obj.contains_key(*field) {
                return Err(denied(
                    "ARC_AUTHORITY_MODEL_CLAIMED",
                    format!(
                        "record asserts its own authority via '{field}'; authority is kernel-asserted per turn, never carried in the payload"
                    ),
                ));
            }
        }
        for (field, expected_value) in expected_binding {
            if !BINDING_FIELDS.contains(field) {
                continue;
            }
            let actual = record_obj.get(*field).and_then(Value::as_str);
            if actual != Some(*expected_value) {
                return Err(denied(
                    "ARC_BINDING_MISMATCH",
                    format!("authenticated record is bound to a different {field}"),
                ));
            }
        }
    }

    Ok(())
}

/// Port of `authenticationBlock`.
pub fn authentication_block(key_id: &str, verified_at: &str) -> Value {
    json!({
        "issuerIdentity": format!("key:{key_id}"),
        "verificationMethod": "capability-signature",
        "perMessage": true,
        "verifiedAt": verified_at,
    })
}

/// Port of `connectionTrustBlock`.
pub fn connection_trust_block(issuer_identity: &str, verified_at: Option<&str>) -> Value {
    json!({
        "issuerIdentity": issuer_identity,
        "verificationMethod": "host-connection-trust",
        "perMessage": false,
        "verifiedAt": verified_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedKeyRing {
        key_id: &'static str,
        key: &'static [u8],
        revoked: bool,
    }
    impl KeyRing for FixedKeyRing {
        fn get(&self, key_id: &str) -> Option<KeyRingEntry<'_>> {
            if key_id == self.key_id {
                Some(KeyRingEntry { key_id: self.key_id, key: self.key, revoked: self.revoked })
            } else {
                None
            }
        }
    }

    fn ring() -> FixedKeyRing {
        FixedKeyRing { key_id: "k1", key: b"secret-key-material", revoked: false }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let record = json!({"schemaVersion": 1, "kind": "x", "sessionId": "s1", "count": 2});
        let bound = ["schemaVersion", "kind", "sessionId", "count"];
        let signed = sign_record(&record, &ring(), "k1", &bound, Some("dom-v1")).unwrap();
        let auth = signed.to_json();
        assert!(verify_record(&record, &auth, &ring(), &bound, &[], Some("dom-v1")).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_record() {
        let record = json!({"schemaVersion": 1, "kind": "x", "count": 2});
        let bound = ["schemaVersion", "kind", "count"];
        let signed = sign_record(&record, &ring(), "k1", &bound, None).unwrap();
        let auth = signed.to_json();
        let tampered = json!({"schemaVersion": 1, "kind": "x", "count": 999});
        let result = verify_record(&tampered, &auth, &ring(), &bound, &[], None);
        assert_eq!(result.unwrap_err().code, "ARC_AUTH_FORGED");
    }

    #[test]
    fn verify_rejects_missing_auth() {
        let record = json!({"a": 1});
        let result = verify_record(&record, &Value::Null, &ring(), &["a"], &[], None);
        assert_eq!(result.unwrap_err().code, "ARC_AUTH_UNAUTHENTICATED");
    }

    #[test]
    fn verify_rejects_revoked_key() {
        let record = json!({"a": 1});
        let bound = ["a"];
        let revoked_ring = FixedKeyRing { key_id: "k1", key: b"secret", revoked: true };
        let signed = sign_record(&record, &revoked_ring, "k1", &bound, None).unwrap();
        let auth = signed.to_json();
        let result = verify_record(&record, &auth, &revoked_ring, &bound, &[], None);
        assert_eq!(result.unwrap_err().code, "ARC_CAPABILITY_REVOKED");
    }

    #[test]
    fn verify_rejects_self_asserted_authority() {
        let record = json!({"a": 1, "authority": "root"});
        let bound = ["a", "authority"];
        let signed = sign_record(&record, &ring(), "k1", &bound, None).unwrap();
        let auth = signed.to_json();
        let result = verify_record(&record, &auth, &ring(), &bound, &[], None);
        assert_eq!(result.unwrap_err().code, "ARC_AUTHORITY_MODEL_CLAIMED");
    }

    #[test]
    fn verify_rejects_binding_mismatch() {
        let record = json!({"a": 1, "runId": "run-a"});
        let bound = ["a", "runId"];
        let signed = sign_record(&record, &ring(), "k1", &bound, None).unwrap();
        let auth = signed.to_json();
        let result = verify_record(&record, &auth, &ring(), &bound, &[("runId", "run-b")], None);
        assert_eq!(result.unwrap_err().code, "ARC_BINDING_MISMATCH");
    }
}
