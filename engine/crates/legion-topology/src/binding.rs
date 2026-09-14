use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::String(text) => Value::String(text.replace('\\', "/")),
        other => other.clone(),
    }
}

pub fn digest(value: &Value) -> String {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_string(&canonical).unwrap_or_else(|_| "null".into());
    format!("sha256:{}", sha256_hex(bytes.as_bytes()))
}

pub fn digest_without_field(value: &Value, field: &str) -> String {
    if let Some(object) = value.as_object() {
        let mut copy = object.clone();
        copy.remove(field);
        return digest(&Value::Object(copy));
    }
    digest(value)
}
