//! Small shared accessors over `controls_support::Value` used by this
//! chunk's three modules. Not a port of any specific JS file -- JS reads
//! object/array fields directly with `.`/`?.`/`??`; these helpers give the
//! same "missing or wrong type => absent" behaviour on the dynamic `Value`
//! tree.

use crate::p5_core::controls_support::Value;

pub(super) fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(key),
        _ => None,
    }
}

/// `value[key] ?? []`, as a slice: missing, null, or non-array reads as
/// empty, matching every `foo.bar ?? []` / `foo.bar?.length` guard in the
/// three ported JS files.
pub(super) fn arr(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items.as_slice(),
        _ => &[],
    }
}

pub(super) fn as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

/// `(value ?? []).map/filter(String)`: a `Value::Array` of strings, other
/// elements dropped; missing/non-array reads as empty.
pub(super) fn str_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(as_str).map(str::to_string).collect(),
        _ => Vec::new(),
    }
}
