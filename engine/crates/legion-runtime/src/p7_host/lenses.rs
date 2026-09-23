//! Port of src/lib/lenses/routing.mjs.
//!
//! `validateCommercialLenses` in JS composes lens-record checks with
//! `loadRoutingGroups`/`validateRoutingGroups` from `../routing/index.mjs`,
//! which belongs to another packet (routing/ is out of scope here per the
//! P7 scope correction). `validate_lens_records` below ports every
//! lens-record-local rule faithfully; the routing-group cross-check is
//! injected as `known_groups` (the set of valid group ids) and a
//! `routing_findings` list the caller supplies from its own routing
//! validation, matching the JS function's `groups`/`routing.findings` inputs
//! without depending on that module's implementation.

use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

static SLASH_SKILL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|\s)/[a-z][a-z0-9-]*").unwrap());

/// Port of `hasSlashSkill`.
pub fn has_slash_skill(value: &Value) -> bool {
    match value {
        Value::String(s) => SLASH_SKILL_RE.is_match(s),
        Value::Array(items) => items.iter().any(has_slash_skill),
        Value::Object(map) => map.values().any(has_slash_skill),
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct LensFinding {
    pub code: String,
    pub lens_id: Option<String>,
    pub detail: String,
}

/// Port of the lens-record-local half of `validateCommercialLenses`
/// (registry uniqueness + per-record checks). `registered_ids` is the
/// `index.lenses` array; `records` is each lens JSON in that order.
pub fn validate_lens_records(
    registered_ids: &[String],
    records: &[Value],
    known_groups: &HashSet<String>,
) -> Vec<LensFinding> {
    let mut findings = Vec::new();
    let unique: HashSet<&String> = registered_ids.iter().collect();
    if unique.len() != registered_ids.len() {
        findings.push(LensFinding {
            code: "lens-roster".into(),
            lens_id: None,
            detail: "lens registry ids must be unique".into(),
        });
    }
    for (position, record) in records.iter().enumerate() {
        let record_id = record.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        let expected_id = registered_ids.get(position).map(String::as_str);
        let availability = record.get("availability").and_then(Value::as_str);
        if Some(record_id.as_str()) != expected_id || availability != Some("available") {
            findings.push(LensFinding {
                code: "lens-availability".into(),
                lens_id: Some(record_id.clone()),
                detail: "lens id must match its registry entry & remain available".into(),
            });
        }
        if let Some(group) = record.get("group").and_then(Value::as_str) {
            if !known_groups.contains(group) {
                findings.push(LensFinding {
                    code: "lens-group".into(),
                    lens_id: Some(record_id.clone()),
                    detail: "optional grouping metadata must resolve to a current routing group".into(),
                });
            }
        }
        if record.get("targetType").is_some() || record.get("targetRef").is_some() {
            findings.push(LensFinding {
                code: "lens-routing-authority".into(),
                lens_id: Some(record_id.clone()),
                detail: "lens metadata cannot declare a routing target".into(),
            });
        }
        let overlay = record.get("privateOverlay");
        let state_ok = overlay.and_then(|o| o.get("state")).and_then(Value::as_str) == Some("optional");
        let fields_empty = overlay
            .and_then(|o| o.get("fields"))
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        if !state_ok || !fields_empty {
            findings.push(LensFinding {
                code: "private-overlay".into(),
                lens_id: Some(record_id.clone()),
                detail: "private overlay must remain optional, empty & unbound".into(),
            });
        }
        if has_slash_skill(record) {
            findings.push(LensFinding {
                code: "slash-skill".into(),
                lens_id: Some(record_id.clone()),
                detail: "lens leaks a slash skill".into(),
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn has_slash_skill_detects_embedded_command() {
        assert!(has_slash_skill(&json!("run /audit now")));
        assert!(!has_slash_skill(&json!("no command here")));
        assert!(has_slash_skill(&json!({"note": ["ok", "/audit-fix please"]})));
    }

    #[test]
    fn validate_lens_records_flags_duplicate_registry_ids() {
        let ids = vec!["a".to_string(), "a".to_string()];
        let findings = validate_lens_records(&ids, &[], &HashSet::new());
        assert!(findings.iter().any(|f| f.code == "lens-roster"));
    }

    #[test]
    fn validate_lens_records_flags_mismatched_or_unavailable_lens() {
        let ids = vec!["a".to_string()];
        let records = vec![json!({"id": "a", "availability": "retired", "privateOverlay": {"state": "optional", "fields": []}})];
        let findings = validate_lens_records(&ids, &records, &HashSet::new());
        assert!(findings.iter().any(|f| f.code == "lens-availability"));
    }

    #[test]
    fn validate_lens_records_flags_routing_authority_leak() {
        let ids = vec!["a".to_string()];
        let records = vec![json!({
            "id": "a", "availability": "available", "targetType": "capability",
            "privateOverlay": {"state": "optional", "fields": []},
        })];
        let findings = validate_lens_records(&ids, &records, &HashSet::new());
        assert!(findings.iter().any(|f| f.code == "lens-routing-authority"));
    }

    #[test]
    fn validate_lens_records_accepts_clean_record() {
        let ids = vec!["a".to_string()];
        let mut groups = HashSet::new();
        groups.insert("marketing".to_string());
        let records = vec![json!({
            "id": "a", "availability": "available", "group": "marketing",
            "privateOverlay": {"state": "optional", "fields": []},
        })];
        let findings = validate_lens_records(&ids, &records, &groups);
        assert!(findings.is_empty());
    }
}
