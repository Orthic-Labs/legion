//! Port of `src/lib/distribution/notices.mjs`.

use serde_json::{json, Value};

/// `renderNotices(components)`. Panics (mirrors the JS `throw`) if no
/// component is shipped.
pub fn render_notices(components: &[Value]) -> String {
    let shipped: Vec<&Value> =
        components.iter().filter(|c| c.get("shipped").and_then(Value::as_bool) == Some(true)).collect();
    if shipped.is_empty() {
        panic!("notices require at least one shipped component");
    }
    shipped
        .iter()
        .map(|component| {
            let name = component.get("name").and_then(Value::as_str).unwrap_or("");
            let license = component.get("license").and_then(Value::as_str).unwrap_or("UNRESOLVED");
            let source = component.get("source").and_then(Value::as_str).unwrap_or("UNRESOLVED");
            format!("## {name}\n\nLicense: {license}\nSource: {source}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `buildNoticeInventory(components)`.
pub fn build_notice_inventory(components: &[Value]) -> Value {
    let shipped: Vec<Value> = components
        .iter()
        .filter(|c| c.get("shipped").and_then(Value::as_bool) == Some(true))
        .cloned()
        .collect();
    let blockers: Vec<Value> = shipped
        .iter()
        .filter(|component| {
            let license = component.get("license").and_then(Value::as_str);
            let source = component.get("source").and_then(Value::as_str);
            let grant = component.get("redistributionGrant").and_then(Value::as_bool);
            license.is_none() || license == Some("") || source.is_none() || source == Some("")
                || (source == Some("external") && grant != Some(true))
        })
        .map(|component| {
            json!({"kind": "redistribution-rights-unresolved", "component": component.get("name").cloned().unwrap_or(Value::Null)})
        })
        .collect();
    let decision = if blockers.is_empty() { "QUALIFIED" } else { "BLOCKED" };
    json!({"components": shipped, "blockers": blockers, "decision": decision})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn qualified_when_no_blockers() {
        let components = vec![json!({"name": "legion", "shipped": true, "license": "MIT", "source": "local"})];
        let inventory = build_notice_inventory(&components);
        assert_eq!(inventory["decision"], "QUALIFIED");
        assert!(render_notices(inventory["components"].as_array().unwrap()).contains("legion"));
    }

    #[test]
    fn blocked_when_external_without_grant() {
        let components = vec![json!({"name": "creator", "shipped": true, "source": "external", "license": Value::Null})];
        let inventory = build_notice_inventory(&components);
        assert_eq!(inventory["blockers"][0]["kind"], "redistribution-rights-unresolved");
    }
}
