//! Port of `skills/designer/engine/scripts/live/event-validation.mjs`.
//!
//! `VISUAL_ACTIONS` is re-exported from `./vocabulary.mjs` there (the
//! `LIVE_COMMANDS` array's `value`s, in palette order); that file is outside
//! this chunk's owned files, so the twelve values are inlined here verbatim
//! from `skills/designer/engine/scripts/live/vocabulary.mjs` as of this
//! port. If the palette ever adds/renames/reorders a command, this constant
//! and the JS source will drift — same maintenance burden the JS comment
//! calls out for the marketing-demo copy.
//!
//! `canCreateInsert` is re-implemented from `./insert-ui.mjs` (also outside
//! this chunk) with the same `hasPrompt || hasComments || hasStrokes` rule.

use serde_json::Value;

pub const VISUAL_ACTIONS: &[&str] = &[
    "impeccable",
    "bolder",
    "quieter",
    "distill",
    "polish",
    "typeset",
    "colorize",
    "layout",
    "morph",
    "animate",
    "delight",
    "overdrive",
];

const FORBIDDEN_MANUAL_EDIT_TEXT_CHARS: &[char] = &['<', '{', '}', '`'];
const INSERT_POSITIONS: &[&str] = &["before", "after"];

fn is_valid_id(v: &Value) -> bool {
    match v.as_str() {
        Some(s) => s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        None => false,
    }
}

fn is_valid_variant_id(v: &Value) -> bool {
    match v.as_str() {
        Some(s) => !s.is_empty() && s.len() <= 3 && s.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// Mirrors `canCreateInsert({ prompt, comments, strokes })`.
pub fn can_create_insert(prompt: Option<&str>, comments: Option<&Value>, strokes: Option<&Value>) -> bool {
    let has_prompt = prompt.map(|p| !p.trim().is_empty()).unwrap_or(false);
    let has_comments = comments.and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false);
    let has_strokes = strokes
        .and_then(Value::as_array)
        .map(|strokes| {
            strokes.iter().any(|s| {
                s.get("points")
                    .and_then(Value::as_array)
                    .map(|pts| pts.len() >= 2)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    has_prompt || has_comments || has_strokes
}

fn validate_manual_edit_text(new_text: &str) -> Vec<char> {
    FORBIDDEN_MANUAL_EDIT_TEXT_CHARS
        .iter()
        .copied()
        .filter(|c| new_text.contains(*c))
        .collect()
}

fn validate_annotation_fields(msg: &Value) -> Option<String> {
    if let Some(v) = msg.get("screenshotPath") {
        if !v.is_null() && !v.is_string() {
            return Some("generate: screenshotPath must be string".to_string());
        }
    }
    if let Some(v) = msg.get("comments") {
        if !v.is_null() && !v.is_array() {
            return Some("generate: comments must be array".to_string());
        }
    }
    if let Some(v) = msg.get("strokes") {
        if !v.is_null() && !v.is_array() {
            return Some("generate: strokes must be array".to_string());
        }
    }
    None
}

fn validate_insert_generate(msg: &Value) -> Option<String> {
    let insert = match msg.get("insert") {
        Some(v) if v.is_object() => v,
        _ => return Some("generate: insert mode requires insert object".to_string()),
    };
    let position = insert.get("position").and_then(Value::as_str).unwrap_or("");
    if !INSERT_POSITIONS.contains(&position) {
        return Some("generate: insert.position must be before or after".to_string());
    }
    let anchor = match insert.get("anchor") {
        Some(v) if v.is_object() => v,
        _ => return Some("generate: insert.anchor required".to_string()),
    };
    let has_tag_name = anchor.get("tagName").map(|v| !v.is_null()).unwrap_or(false)
        && anchor.get("tagName").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
    let has_outer_html = anchor.get("outerHTML").map(|v| !v.is_null()).unwrap_or(false)
        && anchor.get("outerHTML").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
    let has_classes = anchor
        .get("classes")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !has_tag_name && !has_outer_html && !has_classes {
        return Some("generate: insert.anchor needs tagName, classes, or outerHTML".to_string());
    }
    let placeholder = match msg.get("placeholder") {
        Some(v) if v.is_object() => v,
        _ => return Some("generate: insert mode requires placeholder dimensions".to_string()),
    };
    let width_ok = placeholder.get("width").and_then(Value::as_f64).map(f64::is_finite).unwrap_or(false);
    let height_ok = placeholder.get("height").and_then(Value::as_f64).map(f64::is_finite).unwrap_or(false);
    if !width_ok || !height_ok {
        return Some("generate: placeholder width and height must be numbers".to_string());
    }
    let prompt = msg.get("freeformPrompt").and_then(Value::as_str);
    if !can_create_insert(prompt, msg.get("comments"), msg.get("strokes")) {
        return Some("generate: insert requires freeformPrompt or annotations".to_string());
    }
    validate_annotation_fields(msg)
}

fn validate_replace_generate(msg: &Value) -> Option<String> {
    let action_ok = msg
        .get("action")
        .and_then(Value::as_str)
        .map(|a| VISUAL_ACTIONS.contains(&a))
        .unwrap_or(false);
    if !action_ok {
        return Some("generate: invalid action".to_string());
    }
    let has_outer_html = msg
        .get("element")
        .and_then(|e| e.get("outerHTML"))
        .map(|v| !v.is_null())
        .unwrap_or(false);
    if !has_outer_html {
        return Some("generate: missing element context".to_string());
    }
    validate_annotation_fields(msg)
}

fn validate_manual_edit_event(msg: &Value, label: &str) -> Option<String> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    if !is_valid_id(&id) {
        return Some(format!("{label}: missing or malformed id"));
    }
    if !msg.get("pageUrl").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false) {
        return Some(format!("{label}: missing pageUrl"));
    }
    if !msg.get("element").map(|v| v.is_object()).unwrap_or(false) {
        return Some(format!("{label}: missing element"));
    }
    let ops = match msg.get("ops").and_then(Value::as_array) {
        Some(ops) if !ops.is_empty() => ops,
        _ => return Some(format!("{label}: ops must be non-empty array")),
    };
    if ops.len() > 100 {
        return Some(format!("{label}: too many ops (max 100)"));
    }
    for op in ops {
        if op.get("ref").and_then(Value::as_str).is_none() {
            return Some(format!("{label}: op.ref required"));
        }
        if op.get("tag").and_then(Value::as_str).is_none() {
            return Some(format!("{label}: op.tag required"));
        }
        if op.get("originalText").and_then(Value::as_str).is_none() {
            return Some(format!("{label}: op.originalText required"));
        }
        let deleted = op.get("deleted").and_then(Value::as_bool).unwrap_or(false);
        let new_text = op.get("newText").and_then(Value::as_str);
        if !deleted && new_text.is_none() {
            return Some(format!("{label}: text op requires newText"));
        }
        if let Some(new_text) = new_text {
            if !deleted && new_text.trim().is_empty() {
                return Some(format!("{label}: newText cannot be empty"));
            }
            let forbidden = validate_manual_edit_text(new_text);
            if !forbidden.is_empty() {
                let joined: String = forbidden.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(" ");
                return Some(format!(
                    "{label}: newText cannot contain {joined} (plain text only; ask the AI to insert markup)"
                ));
            }
        }
    }
    None
}

/// Mirrors `validateEvent(msg)`. Returns `None` when valid (JS: `null`), or
/// `Some(error message)` matching the JS strings verbatim.
pub fn validate_event(msg: Option<&Value>) -> Option<String> {
    let msg = match msg {
        Some(v) if v.is_object() && v.get("type").map(|t| !t.is_null()).unwrap_or(false) => v,
        _ => return Some("Missing or invalid message".to_string()),
    };
    let event_type = msg.get("type").and_then(Value::as_str).unwrap_or("");
    match event_type {
        "generate" => {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            if !is_valid_id(&id) {
                return Some("generate: missing or malformed id".to_string());
            }
            let count = msg.get("count").and_then(Value::as_i64);
            let count_ok = match count {
                Some(c) => (1..=8).contains(&c) && msg.get("count").and_then(Value::as_f64).map(|f| f.fract() == 0.0).unwrap_or(false),
                None => false,
            };
            if !count_ok {
                return Some("generate: count must be 1-8".to_string());
            }
            if msg.get("mode").and_then(Value::as_str) == Some("insert") {
                return validate_insert_generate(msg);
            }
            validate_replace_generate(msg)
        }
        "accept" => {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            if !is_valid_id(&id) {
                return Some("accept: missing or malformed id".to_string());
            }
            let variant_id = msg.get("variantId").cloned().unwrap_or(Value::Null);
            if !is_valid_variant_id(&variant_id) {
                return Some("accept: missing or malformed variantId".to_string());
            }
            if let Some(pv) = msg.get("paramValues") {
                if !pv.is_null() && !(pv.is_object()) {
                    return Some("accept: paramValues must be an object".to_string());
                }
            }
            None
        }
        "discard" => {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            if is_valid_id(&id) {
                None
            } else {
                Some("discard: missing or malformed id".to_string())
            }
        }
        "checkpoint" => {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            if !is_valid_id(&id) {
                return Some("checkpoint: missing or malformed id".to_string());
            }
            let revision_ok = msg
                .get("revision")
                .and_then(Value::as_i64)
                .map(|r| r >= 0)
                .unwrap_or(false)
                && msg.get("revision").and_then(Value::as_f64).map(|f| f.fract() == 0.0).unwrap_or(false);
            if !revision_ok {
                return Some("checkpoint: revision must be a non-negative integer".to_string());
            }
            if let Some(pv) = msg.get("paramValues") {
                if !pv.is_null() && !pv.is_object() {
                    return Some("checkpoint: paramValues must be an object".to_string());
                }
            }
            None
        }
        "exit" => None,
        "prefetch" => {
            if msg.get("pageUrl").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false) {
                None
            } else {
                Some("prefetch: missing pageUrl".to_string())
            }
        }
        "manual_edits" => validate_manual_edit_event(msg, "manual_edits"),
        "steer" => {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            if !is_valid_id(&id) {
                return Some("steer: missing or malformed id".to_string());
            }
            let message = msg.get("message").and_then(Value::as_str);
            if message.map(|m| m.trim().is_empty()).unwrap_or(true) {
                return Some("steer: message required".to_string());
            }
            if message.unwrap().len() > 4000 {
                return Some("steer: message too long".to_string());
            }
            if let Some(page_url) = msg.get("pageUrl") {
                if !page_url.is_null() && !page_url.is_string() {
                    return Some("steer: pageUrl must be string".to_string());
                }
            }
            None
        }
        other => Some(format!("Unknown event type: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_message() {
        assert_eq!(validate_event(None), Some("Missing or invalid message".to_string()));
        assert_eq!(validate_event(Some(&json!({}))), Some("Missing or invalid message".to_string()));
        assert_eq!(validate_event(Some(&json!("nope"))), Some("Missing or invalid message".to_string()));
    }

    #[test]
    fn unknown_type() {
        assert_eq!(
            validate_event(Some(&json!({"type": "bogus"}))),
            Some("Unknown event type: bogus".to_string())
        );
    }

    #[test]
    fn generate_requires_valid_id_and_count() {
        assert_eq!(
            validate_event(Some(&json!({"type": "generate", "id": "zz", "count": 1}))),
            Some("generate: missing or malformed id".to_string())
        );
        assert_eq!(
            validate_event(Some(&json!({"type": "generate", "id": "0123abcd", "count": 9}))),
            Some("generate: count must be 1-8".to_string())
        );
        assert_eq!(
            validate_event(Some(&json!({"type": "generate", "id": "0123abcd", "count": 1.5}))),
            Some("generate: count must be 1-8".to_string())
        );
    }

    #[test]
    fn generate_replace_mode_validates_action_and_element() {
        let base = json!({"type": "generate", "id": "0123abcd", "count": 2});
        let mut msg = base.clone();
        assert_eq!(validate_event(Some(&msg)), Some("generate: invalid action".to_string()));

        msg["action"] = json!("bolder");
        assert_eq!(validate_event(Some(&msg)), Some("generate: missing element context".to_string()));

        msg["element"] = json!({"outerHTML": "<div></div>"});
        assert_eq!(validate_event(Some(&msg)), None);
    }

    #[test]
    fn generate_insert_mode_validates_full_chain() {
        let mut msg = json!({
            "type": "generate", "id": "0123abcd", "count": 1, "mode": "insert",
        });
        assert_eq!(
            validate_event(Some(&msg)),
            Some("generate: insert mode requires insert object".to_string())
        );

        msg["insert"] = json!({});
        assert_eq!(
            validate_event(Some(&msg)),
            Some("generate: insert.position must be before or after".to_string())
        );

        msg["insert"]["position"] = json!("before");
        assert_eq!(validate_event(Some(&msg)), Some("generate: insert.anchor required".to_string()));

        msg["insert"]["anchor"] = json!({});
        assert_eq!(
            validate_event(Some(&msg)),
            Some("generate: insert.anchor needs tagName, classes, or outerHTML".to_string())
        );

        msg["insert"]["anchor"] = json!({"tagName": "div"});
        assert_eq!(
            validate_event(Some(&msg)),
            Some("generate: insert mode requires placeholder dimensions".to_string())
        );

        msg["placeholder"] = json!({"width": 10, "height": "nope"});
        assert_eq!(
            validate_event(Some(&msg)),
            Some("generate: placeholder width and height must be numbers".to_string())
        );

        msg["placeholder"] = json!({"width": 10, "height": 20});
        assert_eq!(
            validate_event(Some(&msg)),
            Some("generate: insert requires freeformPrompt or annotations".to_string())
        );

        msg["freeformPrompt"] = json!("make it pop");
        assert_eq!(validate_event(Some(&msg)), None);
    }

    #[test]
    fn accept_requires_id_and_variant_id() {
        assert_eq!(
            validate_event(Some(&json!({"type": "accept", "id": "0123abcd", "variantId": "abc"}))),
            Some("accept: missing or malformed variantId".to_string())
        );
        assert_eq!(
            validate_event(Some(&json!({"type": "accept", "id": "0123abcd", "variantId": "1", "paramValues": [1]}))),
            Some("accept: paramValues must be an object".to_string())
        );
        assert_eq!(
            validate_event(Some(&json!({"type": "accept", "id": "0123abcd", "variantId": "1"}))),
            None
        );
    }

    #[test]
    fn discard_and_checkpoint_and_exit_and_prefetch() {
        assert_eq!(validate_event(Some(&json!({"type": "discard", "id": "0123abcd"}))), None);
        assert_eq!(
            validate_event(Some(&json!({"type": "discard", "id": "bad"}))),
            Some("discard: missing or malformed id".to_string())
        );
        assert_eq!(
            validate_event(Some(&json!({"type": "checkpoint", "id": "0123abcd", "revision": -1}))),
            Some("checkpoint: revision must be a non-negative integer".to_string())
        );
        assert_eq!(
            validate_event(Some(&json!({"type": "checkpoint", "id": "0123abcd", "revision": 0}))),
            None
        );
        assert_eq!(validate_event(Some(&json!({"type": "exit"}))), None);
        assert_eq!(
            validate_event(Some(&json!({"type": "prefetch"}))),
            Some("prefetch: missing pageUrl".to_string())
        );
        assert_eq!(validate_event(Some(&json!({"type": "prefetch", "pageUrl": "/x"}))), None);
    }

    #[test]
    fn steer_validates_message_length_and_page_url() {
        assert_eq!(
            validate_event(Some(&json!({"type": "steer", "id": "0123abcd", "message": "  "}))),
            Some("steer: message required".to_string())
        );
        let long = "a".repeat(4001);
        assert_eq!(
            validate_event(Some(&json!({"type": "steer", "id": "0123abcd", "message": long}))),
            Some("steer: message too long".to_string())
        );
        assert_eq!(
            validate_event(Some(&json!({"type": "steer", "id": "0123abcd", "message": "hi", "pageUrl": 5}))),
            Some("steer: pageUrl must be string".to_string())
        );
        assert_eq!(validate_event(Some(&json!({"type": "steer", "id": "0123abcd", "message": "hi"}))), None);
    }

    #[test]
    fn manual_edits_validates_ops() {
        let base = json!({
            "type": "manual_edits", "id": "0123abcd", "pageUrl": "/p",
            "element": {}, "ops": [],
        });
        assert_eq!(
            validate_event(Some(&base)),
            Some("manual_edits: ops must be non-empty array".to_string())
        );

        let mut msg = base.clone();
        msg["ops"] = json!([{"ref": "r1", "tag": "p", "originalText": "hi", "newText": ""}]);
        assert_eq!(
            validate_event(Some(&msg)),
            Some("manual_edits: newText cannot be empty".to_string())
        );

        msg["ops"] = json!([{"ref": "r1", "tag": "p", "originalText": "hi", "newText": "a<b"}]);
        assert_eq!(
            validate_event(Some(&msg)),
            Some("manual_edits: newText cannot contain < (plain text only; ask the AI to insert markup)".to_string())
        );

        msg["ops"] = json!([{"ref": "r1", "tag": "p", "originalText": "hi", "newText": "ok"}]);
        assert_eq!(validate_event(Some(&msg)), None);

        msg["ops"] = json!([{"ref": "r1", "tag": "p", "originalText": "hi", "deleted": true}]);
        assert_eq!(validate_event(Some(&msg)), None);
    }

    #[test]
    fn can_create_insert_rules() {
        assert!(can_create_insert(Some("hi"), None, None));
        assert!(!can_create_insert(Some("  "), None, None));
        assert!(can_create_insert(None, Some(&json!([{"a": 1}])), None));
        assert!(!can_create_insert(None, Some(&json!([])), None));
        assert!(can_create_insert(None, None, Some(&json!([{"points": [[0, 0], [1, 1]]}]))));
        assert!(!can_create_insert(None, None, Some(&json!([{"points": [[0, 0]]}]))));
        assert!(!can_create_insert(None, None, None));
    }
}
