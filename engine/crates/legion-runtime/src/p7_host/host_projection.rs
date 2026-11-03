//! Port of src/lib/host-projection.mjs. Read-only accessor over
//! `src/registry/host-projection.json`; I/O is injected via `projection` so
//! callers supply the parsed document (the JS file's own `readFileSync` +
//! `JSON.parse` + existence check is the caller's concern in Rust, matching
//! how other ported host modules take pre-loaded `serde_json::Value`s).

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
#[error("host projection missing; run: node scripts/generate-host-projection.mjs")]
pub struct HostProjectionMissing;

/// Publicly discoverable domain capabilities, in catalog order. Port of
/// `publicCapabilities`.
pub fn public_capabilities(projection: &Value) -> Vec<Value> {
    projection
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|caps| {
            caps.iter()
                .filter(|c| {
                    c.get("kind").and_then(Value::as_str) == Some("domain-capability")
                        && c.get("discoverability").and_then(Value::as_str) == Some("public")
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Port of `capabilityCatalogBlock`.
pub fn capability_catalog_block(projection: &Value) -> String {
    let capabilities = public_capabilities(projection);
    if capabilities.is_empty() {
        return String::new();
    }
    let mut lines = vec!["## Legion capabilities".to_string(), String::new()];
    for c in &capabilities {
        let name = c.get("name").and_then(Value::as_str).unwrap_or_default();
        let description = c
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        lines.push(format!("- **{name}** — {description}"));
    }
    lines.join("\n")
}

/// Port of `harnessFidelity`.
pub fn harness_fidelity<'a>(projection: &'a Value, id: &str) -> Option<&'a Value> {
    projection
        .get("harnesses")
        .and_then(Value::as_array)
        .and_then(|hs| {
            hs.iter()
                .find(|h| h.get("id").and_then(Value::as_str) == Some(id))
        })
}
