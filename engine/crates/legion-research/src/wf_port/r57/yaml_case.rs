//! Packet r57: small `serde_yaml::Value` access helpers.
//!
//! `generate_pack.py` treats the case YAML as an untyped dict and relies on
//! plain `dict[key]` / `dict.get(key, default)` access, raising `KeyError`
//! (an uncaught Python exception -> traceback on stderr, exit code 1) for a
//! missing required key. These helpers reproduce that behaviour without
//! imposing a rigid schema, so the port stays faithful to a YAML file that
//! carries extra or loosely-typed fields.

use serde_yaml::Value;

/// Mirrors `case[key]`: panics (uncaught-exception equivalent) if absent.
pub fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key)
        .unwrap_or_else(|| panic!("KeyError: '{}'", key))
}

/// Mirrors `case[key]` where the value is a plain scalar rendered as text.
/// Strings pass through as-is; other scalars use their YAML text form so
/// e.g. an unquoted numeric id still prints the same characters.
pub fn s(v: &Value, key: &str) -> String {
    scalar(get(v, key))
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => serde_yaml::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

/// Renders any scalar YAML value as the text Python's implicit `str()` (via
/// `.format()`) would produce for a list element such as a complaint
/// paragraph or a prayer clause.
pub fn scalar_pub(v: &Value) -> String {
    scalar(v)
}

/// Mirrors `case.get(key, default)` for a string default.
pub fn opt_s(v: &Value, key: &str) -> Option<String> {
    v.get(key).filter(|x| !x.is_null()).map(scalar)
}

pub fn s_or(v: &Value, key: &str, default: &str) -> String {
    opt_s(v, key).unwrap_or_else(|| default.to_string())
}

/// Mirrors `case[key]` truthiness check, e.g. `if op.get("cin"):`.
pub fn truthy_s(v: &Value, key: &str) -> Option<String> {
    opt_s(v, key).filter(|s| !s.is_empty())
}

/// Mirrors `case[key]` where the value is expected to be a bool, with a
/// Python-style default (`case.get(key, True)`).
pub fn bool_or(v: &Value, key: &str, default: bool) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// Mirrors `case[key]` where the value is expected to be an integer.
pub fn i64_(v: &Value, key: &str) -> i64 {
    get(v, key)
        .as_i64()
        .unwrap_or_else(|| panic!("expected integer for key '{}'", key))
}

pub fn i64_or(v: &Value, key: &str, default: i64) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or(default)
}

/// Mirrors `case[key]` where the value is expected to be a sequence.
/// Missing key behaves like `case.get(key, [])`, matching every call site
/// in `generate_pack.py` that reads a list-shaped field.
pub fn seq(v: &Value, key: &str) -> Vec<Value> {
    v.get(key)
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default()
}

/// Formats an integer with thousands separators, matching Python's
/// `"{:,}".format(n)` for the non-negative amounts this generator handles.
pub fn comma_int(n: i64) -> String {
    let neg = n < 0;
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    let grouped: String = out.chars().rev().collect();
    if neg {
        format!("-{}", grouped)
    } else {
        grouped
    }
}
