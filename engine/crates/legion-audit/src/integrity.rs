use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{error::AuditError, plan::AuditPlan};

type HmacSha256 = Hmac<Sha256>;

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AuditError> {
    legion_contracts::canonical_json_bytes(value)
        .map_err(|error| AuditError::Invalid(error.to_string()))
}

pub fn digest<T: Serialize>(value: &T) -> Result<String, AuditError> {
    Ok(format!(
        "sha256:{}",
        hex_bytes(&Sha256::digest(canonical_bytes(value)?))
    ))
}

pub fn plan_digest(plan: &AuditPlan) -> Result<String, AuditError> {
    digest(plan)
}

pub fn sign(plan: &AuditPlan, key: &[u8]) -> Result<String, AuditError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| AuditError::Invalid("empty HMAC key".into()))?;
    mac.update(&canonical_bytes(plan)?);
    Ok(format!(
        "hmac-sha256:{}",
        hex_bytes(&mac.finalize().into_bytes())
    ))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn verify(
    plan: &AuditPlan,
    expected_digest: &str,
    signature: Option<&str>,
    key: Option<&[u8]>,
) -> Result<(), AuditError> {
    if plan_digest(plan)? != expected_digest {
        return Err(AuditError::SourceDrift("audit plan digest mismatch".into()));
    }
    match (signature, key) {
        (Some(value), Some(secret)) if sign(plan, secret)? == value => Ok(()),
        (None, None) => Ok(()),
        _ => Err(AuditError::Invalid(
            "audit plan HMAC verification failed".into(),
        )),
    }
}
