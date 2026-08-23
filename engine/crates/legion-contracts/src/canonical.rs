use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("non-finite JSON number")]
    NonFiniteNumber,
}

fn normalize(value: Value) -> Result<Value, CanonicalError> {
    match value {
        Value::Object(object) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in object {
                sorted.insert(key, normalize(value)?);
            }
            let mut output = Map::new();
            for (key, value) in sorted {
                output.insert(key, value);
            }
            Ok(Value::Object(output))
        }
        Value::Array(values) => values
            .into_iter()
            .map(normalize)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Number(number) => {
            if number.as_f64().map(|n| !n.is_finite()).unwrap_or(false) {
                Err(CanonicalError::NonFiniteNumber)
            } else {
                Ok(Value::Number(number))
            }
        }
        other => Ok(other),
    }
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = normalize(serde_json::to_value(value)?)?;
    Ok(serde_json::to_vec(&value)?)
}

pub fn canonical_digest_hex<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    Ok(hex::encode(Sha256::digest(canonical_json_bytes(value)?)))
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    Ok(format!("sha256:{}", canonical_digest_hex(value)?))
}

pub fn canonical_equal<T: Serialize, U: Serialize>(
    left: &T,
    right: &U,
) -> Result<bool, CanonicalError> {
    Ok(canonical_json_bytes(left)? == canonical_json_bytes(right)?)
}
