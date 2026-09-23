//! Port of the pure argument-parsing logic in `src/lib/review/jury.py`
//! (the Council CLI entry point). `main()` itself drives `Engine().run(...)`
//! live and is a bin-level concern outside this module's owned paths;
//! `parse_flag` is the one piece of deterministic, testable logic and is
//! ported faithfully, including its coercion order (bool literals before
//! int, falling back to the raw string).

use serde_json::Value;

/// Port of `parse_flag`: `"k=v"` -> `(k, v)` with `v` coerced to bool
/// (`true`/`yes`/`1` / `false`/`no`/`0`, case-insensitive) then int, else
/// left as the raw string. A flag with no `=` is a bare boolean `true`
/// flag, matching `return s, True`.
pub fn parse_flag(s: &str) -> (String, Value) {
    let Some((k, v)) = s.split_once('=') else {
        return (s.to_string(), Value::Bool(true));
    };
    let lower = v.to_lowercase();
    if matches!(lower.as_str(), "true" | "yes" | "1") {
        return (k.to_string(), Value::Bool(true));
    }
    if matches!(lower.as_str(), "false" | "no" | "0") {
        return (k.to_string(), Value::Bool(false));
    }
    if let Ok(n) = v.parse::<i64>() {
        return (k.to_string(), Value::Number(n.into()));
    }
    (k.to_string(), Value::String(v.to_string()))
}
