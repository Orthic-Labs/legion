//! Python-compatible value helpers shared by the ported Research Core modules.
//!
//! The Python originals operate on loosely typed JSON dicts. These helpers
//! reproduce the exact Python semantics that the ports depend on: truthiness
//! (`x or y`), `str(x)`, `repr` of strings and lists, and the URL quoting
//! helpers from `urllib.parse`.

use serde_json::Value;

/// Python truthiness of an optional JSON value. A missing key is `None`.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

/// Python `str(value)`. A missing key and JSON null both render as `None`.
/// Non-scalar values use their JSON text, which differs from Python's repr.
pub fn py_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// Python `str(value or default)`.
pub fn py_str_or(value: Option<&Value>, default: &str) -> String {
    if truthy(value) {
        py_str(value)
    } else {
        default.to_string()
    }
}

/// Python `value in (None, '')`: only a missing key, JSON null, or the empty string.
pub fn is_none_or_empty_str(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(_) => false,
    }
}

/// Python `value in (None, '', [])`.
pub fn is_null_or_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(Value::Array(items)) => items.is_empty(),
        Some(_) => false,
    }
}

/// Python `repr(str)` for a plain string.
pub fn py_repr_str(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python `repr(list_of_str)`, for example `['a', 'b']`.
pub fn py_list_repr(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|item| py_repr_str(item)).collect();
    format!("[{}]", parts.join(", "))
}

const ALWAYS_SAFE: &str = "_.-~";

fn is_always_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || ALWAYS_SAFE.as_bytes().contains(&byte)
}

/// `urllib.parse.quote(input, safe=safe)`.
pub fn quote(input: &str, safe: &str) -> String {
    let mut out = String::new();
    for &byte in input.as_bytes() {
        if is_always_safe(byte) || safe.as_bytes().contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `urllib.parse.quote_plus(input)` with no extra safe characters.
pub fn quote_plus(input: &str) -> String {
    let mut out = String::new();
    for &byte in input.as_bytes() {
        if byte == b' ' {
            out.push('+');
        } else if is_always_safe(byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `urllib.parse.unquote_plus(raw)`: `+` becomes a space, then percent escapes decode.
pub fn unquote_plus(raw: &str) -> String {
    let bytes: Vec<u8> = raw
        .bytes()
        .map(|byte| if byte == b'+' { b' ' } else { byte })
        .collect();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn truthiness_follows_python_or_semantics() {
        assert!(!truthy(None));
        assert!(!truthy(Some(&Value::Null)));
        assert!(!truthy(Some(&json!(""))));
        assert!(!truthy(Some(&json!([]))));
        assert!(!truthy(Some(&json!(0))));
        assert!(truthy(Some(&json!("x"))));
        assert!(truthy(Some(&json!(2))));
    }

    #[test]
    fn str_and_repr_match_python_shapes() {
        assert_eq!(py_str(None), "None");
        assert_eq!(py_str(Some(&json!(true))), "True");
        assert_eq!(py_str_or(Some(&json!("")), "dflt"), "dflt");
        assert_eq!(py_repr_str("abc"), "'abc'");
        assert_eq!(py_repr_str("it's"), "\"it's\"");
        assert_eq!(
            py_list_repr(&["1".to_string(), "2.5%".to_string()]),
            "['1', '2.5%']"
        );
    }

    #[test]
    fn quoting_matches_urllib() {
        assert_eq!(quote("10.1/x y", ""), "10.1%2Fx%20y");
        assert_eq!(
            quote("https://doi.org/10.1/a", ":/"),
            "https://doi.org/10.1/a"
        );
        assert_eq!(quote("10.1/a", ""), "10.1%2Fa");
        assert_eq!(quote_plus("a b&c"), "a+b%26c");
        assert_eq!(unquote_plus("a+b%26c"), "a b&c");
    }
}
