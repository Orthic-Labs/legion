//! Small `serde_json::Value` accessor helpers mirroring Python's `dict.get(key, default)`
//! chains used throughout `google_report.py`. Not a port of any single Python function --
//! a shared shim the section/chart builders in this packet lean on so each call site reads
//! the same as its Python `data.get("x", {}).get("y")` counterpart.

use serde_json::Value;

/// `d.get(key, {})` -> an object, or an empty (non-mutating) object when absent/wrong type.
pub fn obj<'a>(v: &'a Value, key: &str) -> &'a Value {
    static EMPTY: Value = Value::Null;
    v.get(key).unwrap_or(&EMPTY)
}

pub fn get_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn get_str_or(v: &Value, key: &str, default: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or(default)
        .to_string()
}

pub fn get_f64(v: &Value, key: &str) -> Option<f64> {
    v.get(key).and_then(|x| x.as_f64())
}

pub fn get_f64_or(v: &Value, key: &str, default: f64) -> f64 {
    get_f64(v, key).unwrap_or(default)
}

pub fn get_i64_or(v: &Value, key: &str, default: i64) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(default)
}

pub fn get_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

pub fn arr<'a>(v: &'a Value, key: &str) -> Vec<&'a Value> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

/// HTML-escapes the handful of characters `google_report.py` never escapes either
/// (the Python source interpolates raw strings straight into the HTML it builds) --
/// kept as a no-op passthrough so call sites read identically to the source's
/// f-strings. Present for call sites that need to be explicit about "this value
/// is inserted verbatim, matching Python."
pub fn raw(s: &str) -> String {
    s.to_string()
}

/// Python's `f"{x:,}"` thousands-separator formatting for a non-negative integer.
pub fn thousands(n: i64) -> String {
    let neg = n < 0;
    let s = n.unsigned_abs().to_string();
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// Python's `f"{x:.0%}"` percent formatting (fraction 0..1 -> whole-number percent).
pub fn pct0(fraction: f64) -> String {
    format!("{:.0}%", fraction * 100.0)
}

/// Python truthiness for a `dict.get(key)` result: `None` (key absent),
/// `{}`, `[]`, `""`, `0`, `0.0`, and `false` are all falsy; everything else
/// (including a non-empty object/array, any non-zero number, `true`) is truthy.
/// Used where the source does `if data.get("x"):` / `if a or b:` rather than
/// an explicit presence check.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None => false,
        Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_groups_by_three() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(-1234), "-1,234");
    }

    #[test]
    fn pct0_matches_python_percent_format() {
        assert_eq!(pct0(0.0), "0%");
        assert_eq!(pct0(0.5), "50%");
        assert_eq!(pct0(0.9), "90%");
    }
}
