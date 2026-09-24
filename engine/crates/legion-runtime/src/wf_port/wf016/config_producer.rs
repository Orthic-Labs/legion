//! Port of `src/lib/remediation/producers/config.mjs`.
//!
//! Qualified configuration remediation producers (B7-031). Configuration
//! fixes address one exact key path with one known-safe value. Like the
//! structural producers these only PREVIEW: no filesystem API is used and no
//! apply path exists here.

use serde_json::Value;

use super::mechanical::{Edit, PreviewResult, Producer};

fn get_in<'a>(value: &'a Value, key_path: &[&str]) -> Option<&'a Value> {
    let mut node = value;
    for key in key_path {
        node = node.as_object()?.get(*key)?;
    }
    Some(node)
}

fn set_in(value: &Value, key_path: &[&str], next: Value) -> Value {
    let Some((head, rest)) = key_path.split_first() else { return next };
    let base = match value {
        Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    let mut out = base;
    if rest.is_empty() {
        out.insert((*head).to_string(), next);
    } else {
        let child = out.get(*head).cloned().unwrap_or(Value::Null);
        out.insert((*head).to_string(), set_in(&child, rest, next));
    }
    Value::Object(out)
}

/// Apply config preview edits. Pure and idempotent: an edit whose key
/// already holds the target value is skipped, unrelated keys are preserved,
/// and the document is re-serialized with the indentation it was read with.
///
/// Faithful port of `renderConfigPreview(text, edits)`. Returns the original
/// `text` unchanged for an empty edit list; returns `Err` only where the JS
/// would throw inside `JSON.parse(text)` (the JS function does not catch
/// that error itself — it is the caller's producer `preview` that guards
/// against invalid JSON before edits are ever produced).
pub fn render_config_preview(text: &str, edits: &[Edit]) -> Result<String, serde_json::Error> {
    if edits.is_empty() {
        return Ok(text.to_string());
    }
    let mut document: Value = serde_json::from_str(text)?;
    for edit in edits {
        let Edit::Config { key_path, value, .. } = edit else { continue };
        let key_path: Vec<&str> = key_path.iter().map(String::as_str).collect();
        let current = get_in(&document, &key_path);
        if current == Some(value) {
            continue;
        }
        document = set_in(&document, &key_path, value.clone());
    }
    let indent_len = detect_indent(text);
    let indent = " ".repeat(indent_len);
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    serde::Serialize::serialize(&document, &mut ser).expect("serialization cannot fail");
    let mut rendered = String::from_utf8(buf).expect("valid utf8");
    if text.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

/// `/\n(\s+)\S/.exec(text)?.[1]?.length ?? 2` — the whitespace run right
/// after the first newline, up to (not including) the next non-whitespace
/// character; default 2 spaces when no such run is found.
fn detect_indent(text: &str) -> usize {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\n' {
            continue;
        }
        let mut run = 0usize;
        let mut saw_non_ws_after = false;
        let mut lookahead = chars.clone();
        loop {
            match lookahead.peek() {
                Some(ch) if ch.is_whitespace() => {
                    run += 1;
                    lookahead.next();
                }
                Some(_) => {
                    saw_non_ws_after = true;
                    break;
                }
                None => break,
            }
        }
        if saw_non_ws_after && run > 0 {
            return run;
        }
    }
    2
}

fn key_set_preview(text: &str, key_path: &[&str], value: &Value) -> PreviewResult {
    let document: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            return PreviewResult {
                edits: vec![],
                public_surface_changes: vec![],
                unsupported: Some("configuration is not valid JSON".to_string()),
            }
        }
    };
    if get_in(&document, key_path) == Some(value) {
        return PreviewResult { edits: vec![], public_surface_changes: vec![], unsupported: None };
    }
    let previous = get_in(&document, key_path).cloned().unwrap_or(Value::Null);
    PreviewResult {
        edits: vec![Edit::Config { key_path: key_path.iter().map(|s| s.to_string()).collect(), value: value.clone(), previous }],
        public_surface_changes: vec![],
        unsupported: None,
    }
}

fn cookie_samesite_preview(text: &str, _finding: &Value) -> PreviewResult {
    key_set_preview(text, &["cookie", "sameSite"], &Value::String("lax".to_string()))
}

fn content_type_nosniff_preview(text: &str, _finding: &Value) -> PreviewResult {
    key_set_preview(text, &["headers", "X-Content-Type-Options"], &Value::String("nosniff".to_string()))
}

/// `export const CONFIG_PRODUCERS = Object.freeze([...]);`
pub fn config_producers() -> Vec<Producer> {
    vec![
        Producer {
            id: "config.cookie-samesite",
            version: "1.0.0",
            kind: "config",
            risk: "low",
            rule_ids: vec!["browser-http.cookie-samesite"],
            description: "Set the session cookie SameSite attribute to lax.",
            preconditions: vec!["the configuration declares a cookie object", "no cross-site POST flow depends on SameSite=none"],
            expected_behavior: vec!["session cookies are not sent on cross-site subrequests"],
            affected_families: vec!["security"],
            validation_plan: vec!["config-schema-check", "affected-provider-rerun:security.browser-client"],
            preview: cookie_samesite_preview,
        },
        Producer {
            id: "config.content-type-nosniff",
            version: "1.0.0",
            kind: "config",
            risk: "low",
            rule_ids: vec!["browser-http.content-type-nosniff"],
            description: "Set the X-Content-Type-Options response header to nosniff.",
            preconditions: vec!["the configuration declares a response headers object"],
            expected_behavior: vec!["browsers stop MIME-sniffing responses"],
            affected_families: vec!["security"],
            validation_plan: vec!["config-schema-check", "affected-provider-rerun:security.http-protocol-cache"],
            preview: content_type_nosniff_preview,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cookie_samesite_producer_proposes_edit_when_missing() {
        let producers = config_producers();
        let producer = producers.iter().find(|p| p.id == "config.cookie-samesite").unwrap();
        let preview = (producer.preview)("{\n  \"cookie\": {}\n}", &json!({}));
        assert_eq!(preview.edits.len(), 1);
        let Edit::Config { key_path, value, previous } = &preview.edits[0] else { panic!("expected a config edit") };
        assert_eq!(key_path, &vec!["cookie".to_string(), "sameSite".to_string()]);
        assert_eq!(value, &json!("lax"));
        assert_eq!(previous, &Value::Null);
    }

    #[test]
    fn cookie_samesite_producer_is_idempotent() {
        let producers = config_producers();
        let producer = producers.iter().find(|p| p.id == "config.cookie-samesite").unwrap();
        let preview = (producer.preview)("{\n  \"cookie\": { \"sameSite\": \"lax\" }\n}", &json!({}));
        assert!(preview.edits.is_empty());
    }

    #[test]
    fn invalid_json_is_unsupported() {
        let producers = config_producers();
        let producer = producers.iter().find(|p| p.id == "config.cookie-samesite").unwrap();
        let preview = (producer.preview)("not json", &json!({}));
        assert_eq!(preview.unsupported.as_deref(), Some("configuration is not valid JSON"));
    }

    #[test]
    fn render_config_preview_sets_key_and_preserves_others() {
        let text = "{\n  \"cookie\": {\n    \"secure\": true\n  }\n}\n";
        let edits = vec![Edit::Config { key_path: vec!["cookie".to_string(), "sameSite".to_string()], value: json!("lax"), previous: Value::Null }];
        let rendered = render_config_preview(text, &edits).unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["cookie"]["secure"], json!(true));
        assert_eq!(parsed["cookie"]["sameSite"], json!("lax"));
        assert!(rendered.ends_with('\n'));
        assert!(rendered.contains("  \"cookie\""));
    }

    #[test]
    fn render_config_preview_empty_edits_returns_text_unchanged() {
        let text = "{\"a\":1}";
        assert_eq!(render_config_preview(text, &[]).unwrap(), text);
    }

    #[test]
    fn render_config_preview_skips_edit_already_at_target_value() {
        let text = "{\n  \"cookie\": {\n    \"sameSite\": \"lax\"\n  }\n}";
        let edits = vec![Edit::Config { key_path: vec!["cookie".to_string(), "sameSite".to_string()], value: json!("lax"), previous: json!("lax") }];
        let rendered = render_config_preview(text, &edits).unwrap();
        assert_eq!(rendered, text);
    }
}
