//! Port of `src/lib/provenance/passport.mjs`.
//!
//! Signed change passport per SNIP-PASSPORT-01. Provenance is evidence, not
//! correctness truth. The passport signs content digests, never prose.

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

fn without_signature(body: &Value) -> Value {
    let mut unsigned = body.clone();
    if let Value::Object(map) = &mut unsigned {
        map.remove("signature");
    }
    unsigned
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Port of `passportDigest(body)`.
pub fn passport_digest(body: &Value) -> String {
    let unsigned = without_signature(body);
    let encoded = serde_json::to_string(&unsigned).unwrap_or_default();
    format!("sha256:{}", sha256_hex(encoded.as_bytes()))
}

/// Port of `signPassport(body, signingKey)`.
pub fn sign_passport(body: &Value, signing_key: Option<&str>) -> Value {
    let Some(signing_key) = signing_key.filter(|k| !k.is_empty()) else {
        let mut out = body.clone();
        if let Value::Object(map) = &mut out {
            map.insert(
                "signature".to_string(),
                json!({"algorithm": null, "keyId": null, "value": null}),
            );
        }
        return out;
    };
    let unsigned = without_signature(body);
    let encoded = serde_json::to_string(&unsigned).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(encoded.as_bytes());
    let value = hex::encode(mac.finalize().into_bytes());

    let mut key_material = Vec::with_capacity("passport-key".len() + 1 + signing_key.len());
    key_material.extend_from_slice(b"passport-key");
    key_material.push(0);
    key_material.extend_from_slice(signing_key.as_bytes());
    let key_id = format!("sha256:{}", &sha256_hex(&key_material)[..16]);

    let mut out = unsigned;
    if let Value::Object(map) = &mut out {
        map.insert(
            "signature".to_string(),
            json!({"algorithm": "HMAC-SHA256", "keyId": key_id, "value": value}),
        );
    }
    out
}

/// Port of `verifyPassport(passport, signingKey)`.
pub fn verify_passport(passport: &Value, signing_key: Option<&str>) -> bool {
    let Some(signing_key) = signing_key.filter(|k| !k.is_empty()) else {
        return false;
    };
    let algorithm = passport
        .get("signature")
        .and_then(|s| s.get("algorithm"))
        .and_then(Value::as_str);
    if algorithm != Some("HMAC-SHA256") {
        return false;
    }
    let unsigned = without_signature(passport);
    let encoded = serde_json::to_string(&unsigned).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(encoded.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    passport
        .get("signature")
        .and_then(|s| s.get("value"))
        .and_then(Value::as_str)
        == Some(expected.as_str())
}

/// Input bundle for [`change_passport`], mirroring the JS destructured
/// parameter object.
#[derive(Debug, Clone, Default)]
pub struct ChangePassportInput<'a> {
    pub base_commit: Option<&'a str>,
    pub patch_digest: Option<&'a str>,
    pub finding_ids: &'a [String],
    pub producer: Value,
    pub commands: &'a [String],
    pub verification_artifacts: &'a [String],
    pub created_at: Option<&'a str>,
    pub signing_key: Option<&'a str>,
}

/// Port of `changePassport({...})`.
pub fn change_passport(input: ChangePassportInput<'_>) -> Value {
    let mut finding_ids = input.finding_ids.to_vec();
    finding_ids.sort();
    let mut commands = input.commands.to_vec();
    commands.sort();
    let mut verification_artifacts = input.verification_artifacts.to_vec();
    verification_artifacts.sort();

    let mut body = json!({
        "schemaVersion": 1,
        "kind": "legion-change-passport",
        "baseCommit": input.base_commit,
        "patchDigest": input.patch_digest,
        "findingIds": finding_ids,
        "producer": if input.producer.is_null() { json!({}) } else { input.producer },
        "commands": commands,
        "verificationArtifacts": verification_artifacts,
        "createdAt": input.created_at,
        "signature": Value::Null,
    });
    let digest = passport_digest(&body);
    body["passportDigest"] = json!(digest);
    sign_passport(&body, input.signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_excludes_signature_field() {
        let a = json!({"kind": "x", "signature": null});
        let b = json!({"kind": "x", "signature": {"algorithm": "HMAC-SHA256", "keyId": "k", "value": "v"}});
        assert_eq!(passport_digest(&a), passport_digest(&b));
    }

    #[test]
    fn sign_without_key_yields_null_signature() {
        let body = json!({"kind": "x"});
        let signed = sign_passport(&body, None);
        assert_eq!(signed["signature"]["algorithm"], Value::Null);
        assert_eq!(signed["signature"]["value"], Value::Null);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let body = json!({"kind": "x", "signature": Value::Null});
        let signed = sign_passport(&body, Some("secret"));
        assert_eq!(signed["signature"]["algorithm"], json!("HMAC-SHA256"));
        assert!(verify_passport(&signed, Some("secret")));
        assert!(!verify_passport(&signed, Some("wrong-key")));
    }

    #[test]
    fn verify_rejects_missing_key_or_algorithm() {
        let signed = sign_passport(&json!({"kind": "x"}), Some("secret"));
        assert!(!verify_passport(&signed, None));
        let unsigned = sign_passport(&json!({"kind": "x"}), None);
        assert!(!verify_passport(&unsigned, Some("secret")));
    }

    #[test]
    fn change_passport_sorts_arrays_and_signs() {
        let input = ChangePassportInput {
            base_commit: Some("abc123"),
            patch_digest: Some("sha256:deadbeef"),
            finding_ids: &["z-finding".to_string(), "a-finding".to_string()],
            producer: json!({"tool": "legion"}),
            commands: &["b-cmd".to_string(), "a-cmd".to_string()],
            verification_artifacts: &["z.log".to_string(), "a.log".to_string()],
            created_at: Some("2026-09-24T00:00:00Z"),
            signing_key: Some("secret"),
        };
        let passport = change_passport(input);
        assert_eq!(passport["findingIds"], json!(["a-finding", "z-finding"]));
        assert_eq!(passport["commands"], json!(["a-cmd", "b-cmd"]));
        assert_eq!(passport["verificationArtifacts"], json!(["a.log", "z.log"]));
        assert_eq!(passport["schemaVersion"], json!(1));
        assert_eq!(passport["kind"], json!("legion-change-passport"));
        assert!(passport["passportDigest"].as_str().unwrap().starts_with("sha256:"));
        assert_eq!(passport["signature"]["algorithm"], json!("HMAC-SHA256"));
    }

    #[test]
    fn change_passport_defaults_empty_producer() {
        let input = ChangePassportInput {
            finding_ids: &[],
            commands: &[],
            verification_artifacts: &[],
            producer: Value::Null,
            ..Default::default()
        };
        let passport = change_passport(input);
        assert_eq!(passport["producer"], json!({}));
    }
}
