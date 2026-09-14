use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn digest_json(value: &Value) -> String {
    digest(serde_json::to_string(value).unwrap_or_default().as_bytes())
}

pub fn valid_digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

pub fn string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(ToOwned::to_owned)
}

pub fn path(value: &Value) -> Option<String> {
    value.as_str().map(ToOwned::to_owned).or_else(|| {
        value
            .get("path")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

pub fn files(input: Option<&Value>) -> Vec<String> {
    input
        .and_then(|value| value.get("files"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(path)
        .collect()
}

pub fn same_binding(actual: Option<&Value>, expected: Option<&Value>) -> bool {
    let Some(actual) = actual.and_then(Value::as_object) else {
        return false;
    };
    let Some(expected) = expected.and_then(Value::as_object) else {
        return false;
    };
    actual.get("repositoryRevision") == expected.get("repositoryRevision")
        && actual.get("digest") == expected.get("digest")
}

pub fn exact_binding(actual: Option<&Value>, expected: Option<&Value>) -> bool {
    actual == expected && actual.is_some()
}

pub fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(Map::from_iter(
        entries.into_iter().map(|(key, value)| (key.to_owned(), value)),
    ))
}

pub fn option_number(value: Option<&Value>, default: i64) -> Value {
    value.cloned().unwrap_or_else(|| Value::from(default))
}

pub fn bool_value(value: Option<&Value>, default: bool) -> bool {
    value.and_then(Value::as_bool).unwrap_or(default)
}

pub fn u64_value(value: Option<&Value>, default: u64) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(default)
}

pub fn array(value: Option<&Value>) -> Vec<Value> {
    value.and_then(Value::as_array).cloned().unwrap_or_default()
}
