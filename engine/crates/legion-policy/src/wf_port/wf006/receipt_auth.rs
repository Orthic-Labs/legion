//! Faithful port of `src/lib/guard/compat/audit/receipt-auth.mjs` (S03
//! authenticated receipts: HMAC over an explicit bound-field list).
//!
//! Same three properties as the JS source: the bound-field list is itself
//! authenticated (`boundFieldsDigest`); authority is never self-asserted
//! (`SELF_ASSERTED_AUTHORITY_FIELDS` is refused even with a valid MAC); and
//! binding is checked separately from the MAC (`ARC_BINDING_MISMATCH`, not
//! `ARC_AUTH_FORGED`).

use std::collections::BTreeMap;

use super::canonical::{canonical_json, constant_time_equal, digest, hmac_sha256_hex, project_bound_fields, Json};
use super::errors::{ArcCode, ArcaneError, Decision};

pub const MAC_ALGORITHM: &str = "HMAC-SHA256";

pub const EFFECT_RECEIPT_BOUND_FIELDS: &[&str] = &[
    "schemaVersion", "kind", "receiptId", "requestId", "runId", "contractId", "taskId",
    "requested", "authorized", "observed", "match", "sourceRevision", "idempotencyKey", "observedAt",
];

pub const EVIDENCE_RECEIPT_BOUND_FIELDS: &[&str] = &[
    "schemaVersion", "kind", "evidenceId", "runId", "taskId", "contractId", "producerAuthority",
    "capability", "observation", "evidenceClass", "sourceRevision", "dependsOn", "observedAt",
];

const SELF_ASSERTED_AUTHORITY_FIELDS: &[&str] =
    &["authority", "callerAuthority", "assertedAuthority", "trust_class", "trustClass"];

const BINDING_FIELDS: &[&str] =
    &["runId", "taskId", "workspace", "workspaceId", "operation", "sessionId", "contractId"];

fn digest_of_bound_field_list(bound_fields: &[&str]) -> String {
    let arr = Json::Arr(bound_fields.iter().map(|f| Json::str(*f)).collect());
    digest(canonical_json(&arr).unwrap().as_bytes())
}

/// A signing key. Mirrors the JS `keyRing.get(keyId)` contract: absent key
/// is a fail-closed throw (`ARC_AUTH_KEY_UNAVAILABLE`), never a denial.
pub trait KeyRing {
    fn get(&self, key_id: &str) -> Result<(&str, &[u8], bool /* revoked */), ArcaneError>;
}

pub struct StaticKeyRing {
    /// keyId -> (key bytes, revoked)
    keys: BTreeMap<String, (Vec<u8>, bool)>,
}

impl StaticKeyRing {
    pub fn new() -> Self {
        Self { keys: BTreeMap::new() }
    }
    pub fn with_key(mut self, key_id: &str, key: &[u8], revoked: bool) -> Self {
        self.keys.insert(key_id.to_string(), (key.to_vec(), revoked));
        self
    }
}

impl KeyRing for StaticKeyRing {
    fn get(&self, key_id: &str) -> Result<(&str, &[u8], bool), ArcaneError> {
        match self.keys.get_key_value(key_id) {
            Some((k, (key, revoked))) => Ok((k.as_str(), key.as_slice(), *revoked)),
            None => Err(ArcaneError::new(ArcCode::ArcAuthKeyUnavailable, format!("signing key {key_id} is unavailable"))
                .with_detail("keyId", key_id)),
        }
    }
}

fn mac_over(key: &[u8], record: &Json, bound_fields: &[&str], mac_domain: Option<&str>) -> Result<String, ArcaneError> {
    let projected = project_bound_fields(record, bound_fields)
        .map_err(|e| ArcaneError::new(ArcCode::ArcAuthForged, e.message.clone()).with_detail("field", e.path.clone()))?;
    let bound_fields_json = Json::Arr(bound_fields.iter().map(|f| Json::str(*f)).collect());
    let message = match mac_domain {
        None => Json::Obj(vec![
            ("alg".into(), Json::str(MAC_ALGORITHM)),
            ("boundFields".into(), bound_fields_json),
            ("subject".into(), projected),
        ]),
        Some(domain) => Json::Obj(vec![
            ("alg".into(), Json::str(MAC_ALGORITHM)),
            ("boundFields".into(), bound_fields_json),
            ("macDomain".into(), Json::str(domain)),
            ("subject".into(), projected),
        ]),
    };
    let text = canonical_json(&message).map_err(|e| ArcaneError::new(ArcCode::ArcAuthForged, e.message.clone()))?;
    Ok(hmac_sha256_hex(key, text.as_bytes()))
}

#[derive(Debug, Clone)]
pub struct SignedAuth {
    pub alg: String,
    pub key_id: String,
    pub mac: String,
    pub mac_domain: Option<String>,
    pub bound_fields_digest: String,
}

/// Sign `record` over `bound_fields` with the key `key_id`. Fail-closed
/// (`Err(ArcaneError)`) when the key is absent, matching the JS throw.
pub fn sign_record(
    record: &Json,
    keyring: &dyn KeyRing,
    key_id: &str,
    bound_fields: &[&str],
    mac_domain: Option<&str>,
) -> Result<SignedAuth, ArcaneError> {
    if bound_fields.is_empty() {
        return Err(ArcaneError::new(ArcCode::ArcAuthForged, "signRecord requires a non-empty boundFields list"));
    }
    let (resolved_key_id, key, _revoked) = keyring.get(key_id)?;
    Ok(SignedAuth {
        alg: MAC_ALGORITHM.to_string(),
        key_id: resolved_key_id.to_string(),
        mac: mac_over(key, record, bound_fields, mac_domain)?,
        mac_domain: mac_domain.map(|s| s.to_string()),
        bound_fields_digest: digest_of_bound_field_list(bound_fields),
    })
}

/// Presented authentication material on a record under verification. `None`
/// or a legacy `signature_or_mac` field are both distinct denial paths.
pub enum PresentedAuth<'a> {
    None,
    LegacyDigest,
    Signed { alg: &'a str, key_id: &'a str, mac: &'a str, mac_domain: Option<&'a str>, bound_fields_digest: Option<&'a str> },
}

pub struct VerifyOpts<'a> {
    pub bound_fields: &'a [&'a str],
    /// field -> expected value, restricted to `BINDING_FIELDS`.
    pub expected_binding: BTreeMap<&'a str, &'a str>,
    /// `None` means "accept the mac_domain the record itself presents" (JS
    /// `macDomain: undefined`); `Some(None)` is not representable here since
    /// JS distinguishes `undefined` from `null` — callers wanting to force
    /// "no domain" pass `Some("")` is NOT used; instead pass
    /// `force_mac_domain: Some(None)` via the dedicated field below.
    pub force_mac_domain: Option<Option<&'a str>>,
}

/// Verify `auth` over `record`. Returns a `Decision` (a denial is data the
/// caller must record); the sole throwing path is an unavailable key.
pub fn verify_record(
    record: &Json,
    auth: PresentedAuth,
    keyring: &dyn KeyRing,
    opts: &VerifyOpts,
) -> Result<Decision, ArcaneError> {
    // 1. Legacy self-hash, checked first.
    if let PresentedAuth::LegacyDigest = auth {
        return Ok(Decision::deny(
            ArcCode::ArcAuthLegacyDigest,
            "legacy predecessor signature_or_mac is a self-hash by the producing process, not authentication (S00 finding 1)",
            vec![("field".into(), "signature_or_mac".into())],
        ));
    }

    let (alg, key_id, mac, mac_domain, bound_fields_digest) = match &auth {
        PresentedAuth::None => {
            return Ok(Decision::deny(
                ArcCode::ArcAuthUnauthenticated,
                "no authentication material present on this record",
                vec![],
            ))
        }
        PresentedAuth::LegacyDigest => unreachable!(),
        PresentedAuth::Signed { alg, key_id, mac, mac_domain, bound_fields_digest } => {
            (*alg, *key_id, *mac, *mac_domain, *bound_fields_digest)
        }
    };

    if alg != MAC_ALGORITHM {
        return Ok(Decision::deny(
            ArcCode::ArcAuthForged,
            format!("unsupported MAC algorithm: {alg}"),
            vec![("alg".into(), alg.into()), ("expected".into(), MAC_ALGORITHM.into())],
        ));
    }

    if let Some(forced) = opts.force_mac_domain {
        if forced != mac_domain {
            return Ok(Decision::deny(
                ArcCode::ArcAuthForged,
                "MAC domain does not match verifier requirement",
                vec![
                    ("expectedMacDomain".into(), forced.unwrap_or("").into()),
                    ("presented".into(), mac_domain.unwrap_or("").into()),
                ],
            ));
        }
    }

    // 3. The covered field list must be exactly the one the verifier demands.
    let expected_fields_digest = digest_of_bound_field_list(opts.bound_fields);
    if !constant_time_equal(bound_fields_digest.unwrap_or("").as_bytes(), expected_fields_digest.as_bytes()) {
        return Ok(Decision::deny(
            ArcCode::ArcAuthForged,
            "signed bound-field list does not match the verifier's required field list",
            vec![
                ("expectedBoundFieldsDigest".into(), expected_fields_digest),
                ("presented".into(), bound_fields_digest.unwrap_or("").into()),
            ],
        ));
    }

    // 4. Key must be present and usable. Absent key => fail closed.
    let (resolved_key_id, key, revoked) = keyring.get(key_id)?;
    if revoked {
        return Ok(Decision::deny(
            ArcCode::ArcCapabilityRevoked,
            format!("signing key {resolved_key_id} is revoked"),
            vec![("keyId".into(), resolved_key_id.into())],
        ));
    }

    // 5. The MAC itself.
    let effective_domain = if opts.force_mac_domain.is_some() { opts.force_mac_domain.unwrap() } else { mac_domain };
    let expected_mac = match mac_over(key, record, opts.bound_fields, effective_domain) {
        Ok(m) => m,
        Err(e) => {
            return Ok(Decision::deny(
                ArcCode::ArcAuthForged,
                format!("record is missing a bound field: {}", e.detail.iter().find(|(k, _)| k == "field").map(|(_, v)| v.as_str()).unwrap_or("unknown")),
                e.detail,
            ))
        }
    };
    if !constant_time_equal(mac.as_bytes(), expected_mac.as_bytes()) {
        return Ok(Decision::deny(
            ArcCode::ArcAuthForged,
            "MAC does not verify over the bound fields",
            vec![("keyId".into(), key_id.into())],
        ));
    }

    // 6. A valid MAC over a self-asserted authority is still not authority.
    for field in SELF_ASSERTED_AUTHORITY_FIELDS {
        if let Some(value) = record.get(field) {
            let value_str = match value {
                Json::Str(s) => s.clone(),
                other => canonical_json(other).unwrap_or_default(),
            };
            return Ok(Decision::deny(
                ArcCode::ArcAuthorityModelClaimed,
                format!("record asserts its own authority via '{field}'; authority is kernel-asserted per turn, never carried in the payload"),
                vec![("field".into(), (*field).into()), ("value".into(), value_str)],
            ));
        }
    }

    // 7. Right signature, wrong subject.
    for field in BINDING_FIELDS {
        if let Some(expected) = opts.expected_binding.get(field) {
            let actual = record.get(field).and_then(|v| v.as_str()).unwrap_or("");
            if actual != *expected {
                return Ok(Decision::deny(
                    ArcCode::ArcBindingMismatch,
                    format!("authenticated record is bound to a different {field}"),
                    vec![("field".into(), (*field).into()), ("expected".into(), (*expected).into()), ("actual".into(), actual.into())],
                ));
            }
        }
    }

    Ok(Decision::allow(vec![("keyId".into(), key_id.into())]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pairs: Vec<(&str, &str)>) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), Json::str(v))).collect())
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let keyring = StaticKeyRing::new().with_key("k1", b"secret-key-material", false);
        let record = record(vec![("runId", "run-1"), ("taskId", "task-1")]);
        let bound = &["runId", "taskId"];
        let signed = sign_record(&record, &keyring, "k1", bound, None).unwrap();
        let auth = PresentedAuth::Signed {
            alg: &signed.alg,
            key_id: &signed.key_id,
            mac: &signed.mac,
            mac_domain: signed.mac_domain.as_deref(),
            bound_fields_digest: Some(&signed.bound_fields_digest),
        };
        let opts = VerifyOpts { bound_fields: bound, expected_binding: BTreeMap::new(), force_mac_domain: None };
        let d = verify_record(&record, auth, &keyring, &opts).unwrap();
        assert!(d.allowed, "{d:?}");
    }

    #[test]
    fn tampered_record_fails_mac() {
        let keyring = StaticKeyRing::new().with_key("k1", b"secret-key-material", false);
        let record = record(vec![("runId", "run-1")]);
        let bound = &["runId"];
        let signed = sign_record(&record, &keyring, "k1", bound, None).unwrap();
        let tampered = record_with(&record, "runId", "run-2");
        let auth = PresentedAuth::Signed {
            alg: &signed.alg,
            key_id: &signed.key_id,
            mac: &signed.mac,
            mac_domain: None,
            bound_fields_digest: Some(&signed.bound_fields_digest),
        };
        let opts = VerifyOpts { bound_fields: bound, expected_binding: BTreeMap::new(), force_mac_domain: None };
        let d = verify_record(&tampered, auth, &keyring, &opts).unwrap();
        assert!(!d.allowed);
        assert_eq!(d.code, Some(ArcCode::ArcAuthForged));
    }

    fn record_with(base: &Json, key: &str, value: &str) -> Json {
        if let Json::Obj(pairs) = base {
            Json::Obj(pairs.iter().map(|(k, v)| if k == key { (k.clone(), Json::str(value)) } else { (k.clone(), v.clone()) }).collect())
        } else {
            base.clone()
        }
    }

    #[test]
    fn legacy_digest_is_refused() {
        let keyring = StaticKeyRing::new();
        let record = record(vec![("runId", "run-1")]);
        let opts = VerifyOpts { bound_fields: &["runId"], expected_binding: BTreeMap::new(), force_mac_domain: None };
        let d = verify_record(&record, PresentedAuth::LegacyDigest, &keyring, &opts).unwrap();
        assert_eq!(d.code, Some(ArcCode::ArcAuthLegacyDigest));
    }

    #[test]
    fn no_auth_material_is_unauthenticated() {
        let keyring = StaticKeyRing::new();
        let record = record(vec![("runId", "run-1")]);
        let opts = VerifyOpts { bound_fields: &["runId"], expected_binding: BTreeMap::new(), force_mac_domain: None };
        let d = verify_record(&record, PresentedAuth::None, &keyring, &opts).unwrap();
        assert_eq!(d.code, Some(ArcCode::ArcAuthUnauthenticated));
    }

    #[test]
    fn self_asserted_authority_is_refused_even_with_valid_mac() {
        let keyring = StaticKeyRing::new().with_key("k1", b"secret", false);
        let record = record(vec![("runId", "run-1"), ("authority", "alchemist")]);
        let bound = &["runId"]; // authority not in bound fields, still refused
        let signed = sign_record(&record, &keyring, "k1", bound, None).unwrap();
        let auth = PresentedAuth::Signed {
            alg: &signed.alg,
            key_id: &signed.key_id,
            mac: &signed.mac,
            mac_domain: None,
            bound_fields_digest: Some(&signed.bound_fields_digest),
        };
        let opts = VerifyOpts { bound_fields: bound, expected_binding: BTreeMap::new(), force_mac_domain: None };
        let d = verify_record(&record, auth, &keyring, &opts).unwrap();
        assert_eq!(d.code, Some(ArcCode::ArcAuthorityModelClaimed));
    }

    #[test]
    fn revoked_key_is_denied() {
        let keyring = StaticKeyRing::new().with_key("k1", b"secret", true);
        let record = record(vec![("runId", "run-1")]);
        let bound = &["runId"];
        // Sign with a not-yet-revoked copy of the same key material so the
        // MAC itself verifies; only the revoked flag should trip the denial.
        let signing_ring = StaticKeyRing::new().with_key("k1", b"secret", false);
        let signed = sign_record(&record, &signing_ring, "k1", bound, None).unwrap();
        let auth = PresentedAuth::Signed {
            alg: &signed.alg,
            key_id: &signed.key_id,
            mac: &signed.mac,
            mac_domain: None,
            bound_fields_digest: Some(&signed.bound_fields_digest),
        };
        let opts = VerifyOpts { bound_fields: bound, expected_binding: BTreeMap::new(), force_mac_domain: None };
        let d = verify_record(&record, auth, &keyring, &opts).unwrap();
        assert_eq!(d.code, Some(ArcCode::ArcCapabilityRevoked));
    }

    #[test]
    fn binding_mismatch_is_distinct_from_forgery() {
        let keyring = StaticKeyRing::new().with_key("k1", b"secret", false);
        let record = record(vec![("runId", "run-1")]);
        let bound = &["runId"];
        let signed = sign_record(&record, &keyring, "k1", bound, None).unwrap();
        let auth = PresentedAuth::Signed {
            alg: &signed.alg,
            key_id: &signed.key_id,
            mac: &signed.mac,
            mac_domain: None,
            bound_fields_digest: Some(&signed.bound_fields_digest),
        };
        let mut expected_binding = BTreeMap::new();
        expected_binding.insert("runId", "run-OTHER");
        let opts = VerifyOpts { bound_fields: bound, expected_binding, force_mac_domain: None };
        let d = verify_record(&record, auth, &keyring, &opts).unwrap();
        assert_eq!(d.code, Some(ArcCode::ArcBindingMismatch));
    }

    #[test]
    fn key_unavailable_is_a_fail_closed_error_not_a_denial() {
        let keyring = StaticKeyRing::new();
        let record = record(vec![("runId", "run-1")]);
        let bound = &["runId"];
        let err = sign_record(&record, &keyring, "missing-key", bound, None).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcAuthKeyUnavailable);
        assert!(err.fail_closed());
    }

    #[test]
    fn bound_field_digest_mismatch_is_forged() {
        let keyring = StaticKeyRing::new().with_key("k1", b"secret", false);
        let record = record(vec![("runId", "run-1"), ("taskId", "task-1")]);
        // Signed over a narrower field list than the verifier requires.
        let signed = sign_record(&record, &keyring, "k1", &["runId"], None).unwrap();
        let auth = PresentedAuth::Signed {
            alg: &signed.alg,
            key_id: &signed.key_id,
            mac: &signed.mac,
            mac_domain: None,
            bound_fields_digest: Some(&signed.bound_fields_digest),
        };
        let opts = VerifyOpts { bound_fields: &["runId", "taskId"], expected_binding: BTreeMap::new(), force_mac_domain: None };
        let d = verify_record(&record, auth, &keyring, &opts).unwrap();
        assert_eq!(d.code, Some(ArcCode::ArcAuthForged));
    }
}
