use crate::error::ArcaneError;
use crate::key_ring::KeyRing;
use hmac::{Hmac, KeyInit, Mac};
use legion_contracts::{canonical_digest, canonical_json_bytes};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const MAC_ALGORITHM: &str = "HMAC-SHA256";

pub fn sign_record(
    record: &Value,
    key_ring: &KeyRing,
    key_id: &str,
    bound_fields: &[&str],
    mac_domain: Option<&str>,
) -> Result<Value, ArcaneError> {
    let handle = key_ring.get(key_id)?;
    let projected = project_bound_fields(record, bound_fields)?;
    let message = if let Some(domain) = mac_domain {
        json!({"alg":MAC_ALGORITHM,"boundFields":bound_fields,"macDomain":domain,"subject":projected})
    } else {
        json!({"alg":MAC_ALGORITHM,"boundFields":bound_fields,"subject":projected})
    };
    let bytes = canonical_json_bytes(&message)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&handle.key)
        .map_err(|_| ArcaneError::typed("ARC_AUTH_FORGED", "invalid key"))?;
    mac.update(&bytes);
    let mut auth = Map::new();
    auth.insert("alg".into(), Value::String(MAC_ALGORITHM.into()));
    auth.insert("keyId".into(), Value::String(handle.key_id));
    auth.insert(
        "mac".into(),
        Value::String(hex::encode(mac.finalize().into_bytes())),
    );
    if let Some(domain) = mac_domain {
        auth.insert("macDomain".into(), Value::String(domain.into()));
    }
    auth.insert(
        "boundFieldsDigest".into(),
        Value::String(canonical_digest(&json!(bound_fields))?),
    );
    Ok(Value::Object(auth))
}

#[derive(Debug, Clone)]
pub struct VerifyDecision {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: Option<String>,
}

pub fn verify_record(
    record: &Value,
    auth: Option<&Value>,
    key_ring: &KeyRing,
    bound_fields: &[&str],
    expected_binding: &Map<String, Value>,
    mac_domain: Option<&str>,
) -> Result<VerifyDecision, ArcaneError> {
    if let Some(auth) = auth {
        if auth.get("signature_or_mac").is_some() {
            return Ok(deny(
                "ARC_AUTH_LEGACY_DIGEST",
                "legacy predecessor signature_or_mac is a self-hash by the producing process, not authentication (S00 finding 1)",
            ));
        }
    }
    let auth =
        auth.ok_or_else(|| ArcaneError::typed("ARC_AUTH_UNAUTHENTICATED", "no authentication"))?;
    let mac = auth
        .get("mac")
        .and_then(Value::as_str)
        .ok_or_else(|| ArcaneError::typed("ARC_AUTH_UNAUTHENTICATED", "no authentication"))?;
    let key_id = auth
        .get("keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| ArcaneError::typed("ARC_AUTH_UNAUTHENTICATED", "no authentication"))?;
    if auth.get("alg").and_then(Value::as_str) != Some(MAC_ALGORITHM) {
        return Ok(deny("ARC_AUTH_FORGED", "unsupported MAC algorithm"));
    }
    if mac_domain.is_some() && auth.get("macDomain").and_then(Value::as_str) != mac_domain {
        return Ok(deny(
            "ARC_AUTH_FORGED",
            "MAC domain does not match verifier requirement",
        ));
    }
    let expected_fields_digest = legion_contracts::canonical_digest(&json!(bound_fields))?;
    if auth.get("boundFieldsDigest").and_then(Value::as_str)
        != Some(expected_fields_digest.as_str())
    {
        return Ok(deny(
            "ARC_AUTH_FORGED",
            "signed bound-field list does not match the verifier’s required field list",
        ));
    }
    let handle = key_ring.get(key_id)?;
    let expected_mac = mac_over(&handle.key, record, bound_fields, mac_domain)?;
    if !constant_time_equal(mac, &expected_mac) {
        return Ok(deny(
            "ARC_AUTH_FORGED",
            "MAC does not verify over the bound fields",
        ));
    }
    for field in [
        "authority",
        "callerAuthority",
        "assertedAuthority",
        "trust_class",
        "trustClass",
    ] {
        if record.get(field).is_some() {
            return Ok(deny(
                "ARC_AUTHORITY_MODEL_CLAIMED",
                "record asserts its own authority",
            ));
        }
    }
    for (field, expected) in expected_binding {
        if record.get(field) != Some(expected) {
            return Ok(deny(
                "ARC_BINDING_MISMATCH",
                format!("authenticated record is bound to a different {field}"),
            ));
        }
    }
    Ok(VerifyDecision {
        allowed: true,
        code: None,
        message: None,
    })
}

fn deny(code: &'static str, message: impl Into<String>) -> VerifyDecision {
    VerifyDecision {
        allowed: false,
        code: Some(code),
        message: Some(message.into()),
    }
}

fn project_bound_fields(record: &Value, fields: &[&str]) -> Result<Value, ArcaneError> {
    let object = record.as_object().ok_or_else(|| {
        ArcaneError::typed("ARC_CANONICALIZATION_FAILED", "record must be an object")
    })?;
    let mut out = Map::new();
    for field in fields {
        let value = object.get(*field).ok_or_else(|| {
            ArcaneError::typed(
                "ARC_CANONICALIZATION_FAILED",
                format!("bound field missing: {field}"),
            )
        })?;
        out.insert(field.to_string(), value.clone());
    }
    Ok(Value::Object(out))
}

fn mac_over(
    key: &[u8],
    record: &Value,
    bound_fields: &[&str],
    mac_domain: Option<&str>,
) -> Result<String, ArcaneError> {
    let subject = project_bound_fields(record, bound_fields)?;
    let message = if let Some(domain) = mac_domain {
        json!({
            "alg": MAC_ALGORITHM,
            "boundFields": bound_fields,
            "macDomain": domain,
            "subject": subject,
        })
    } else {
        json!({
            "alg": MAC_ALGORITHM,
            "boundFields": bound_fields,
            "subject": subject,
        })
    };
    let bytes = canonical_json_bytes(&message)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| ArcaneError::typed("ARC_AUTH_FORGED", "invalid key material"))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}
