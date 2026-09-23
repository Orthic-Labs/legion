//! Port of `src/lib/inventory/external-systems/**`.

use std::collections::BTreeSet;

use regex::Regex;
use serde_json::{json, Value};

use super::binding::digest;
use super::error::InventoryError;

type R<T> = Result<T, InventoryError>;

const KINDS: &[(&str, &str)] = &[
    ("payments", r"(?i)stripe|paypal|braintree"),
    ("identity", r"(?i)auth0|okta|oauth|cognito"),
    ("messaging", r"(?i)twilio|sendgrid|mailgun|firebase.*messag"),
    ("analytics", r"(?i)segment|analytics|posthog|amplitude"),
    ("storage", r"(?i)s3|blob|storage|cloudinary"),
    ("ai", r"(?i)openai|anthropic|bedrock|vertex.*ai"),
    ("monitoring", r"(?i)sentry|datadog|newrelic|opentelemetry"),
    ("dns-cdn", r"(?i)cloudflare|route53|fastly"),
    ("support", r"(?i)zendesk|intercom|freshdesk"),
    ("queue", r"(?i)sqs|pubsub|rabbitmq|kafka"),
    ("database", r"(?i)supabase|firebase|mongodb|planetscale"),
    ("store", r"(?i)appstore|playstore|npmjs|pypi"),
    ("signing", r"(?i)codesign|authenticode|notary"),
    ("deployment", r"(?i)vercel|netlify|heroku|fly\.io"),
];

/// Port of `externalSystem(record)` — the minimal contract check.
pub fn external_system(record: Value) -> R<Value> {
    let has = |key: &str| !matches!(record.get(key), None | Some(Value::Null));
    if !has("id") || !has("kind") || !has("status") {
        return Err(InventoryError::new(
            "external system requires id, kind, status",
        ));
    }
    Ok(record)
}

fn path_of(item: &Value) -> String {
    match item {
        Value::Object(map) => map
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Port of `discoverExternalSystems`.
pub fn discover_external_systems(projection: &Value, components: &Value, binding: &Value) -> Value {
    let files: Vec<String> = projection
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(path_of)
        .filter(|p| !p.is_empty())
        .collect();

    let dependencies = projection
        .get("dependencies")
        .or_else(|| projection.get("packages"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let dependency_names: Vec<String> = match &dependencies {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Object(map) => map
                    .get("name")
                    .or_else(|| map.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        Value::Object(map) => map.keys().cloned().collect(),
        _ => vec![],
    };

    let declared: Vec<Value> = projection
        .get("externalSystems")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|item| match item {
            Value::String(name) => json!({"name": name, "evidencePaths": []}),
            other => other.clone(),
        })
        .collect();

    let mut evidence: Vec<String> = files.clone();
    evidence.extend(dependency_names.iter().map(|name| format!("dependency:{name}")));
    for d in &declared {
        for p in d
            .get("evidencePaths")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(s) = p.as_str() {
                evidence.push(s.to_string());
            }
        }
    }

    let component_ids: Vec<Value> = components
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|c| {
            c.get("external") == Some(&Value::Bool(true))
                || c.get("kind") == Some(&Value::String("integration".into()))
        })
        .filter_map(|c| c.get("id").cloned())
        .collect();

    let mut systems: Vec<Value> = Vec::new();
    for (kind, pattern) in KINDS {
        let re = Regex::new(pattern).expect("static regex");
        let evidence_paths: Vec<String> = evidence.iter().filter(|p| re.is_match(p)).cloned().collect();
        let declarations: Vec<&Value> = declared
            .iter()
            .filter(|d| {
                let name = d.get("name").and_then(Value::as_str).unwrap_or("");
                re.is_match(name)
            })
            .collect();
        if evidence_paths.is_empty() && declarations.is_empty() {
            continue;
        }
        let sorted: BTreeSet<String> = evidence_paths.into_iter().collect();
        systems.push(json!({
            "id": format!("external:{kind}"),
            "kind": kind,
            "status": if sorted.is_empty() { "unknown" } else { "referenced" },
            "evidencePaths": sorted.into_iter().collect::<Vec<_>>(),
            "targetIds": projection.get("externalTargets").and_then(|t| t.get(kind)).cloned().unwrap_or_else(|| json!([])),
            "componentIds": component_ids.clone(),
            "dataClasses": projection.get("externalDataClasses").and_then(|t| t.get(kind)).cloned().unwrap_or_else(|| json!([])),
            "environments": [],
            "credentialsPolicy": "host-owned-unproven",
            "freshnessRequirement": "external-attestation-required",
            "binding": binding,
        }));
    }

    let unknown: Vec<Value> = projection
        .get("externalEndpoints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|endpoint| {
            let text = match endpoint {
                Value::String(s) => s.to_lowercase(),
                other => other.to_string().to_lowercase(),
            };
            !systems.iter().any(|s| {
                let kind = s.get("kind").and_then(Value::as_str).unwrap_or("");
                text.contains(kind)
            })
        })
        .map(|endpoint| {
            let endpoint_str = match endpoint {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let normalized = endpoint_str.replace('\\', "/").to_lowercase();
            let hashed = digest(&Value::String(normalized));
            let suffix = &hashed[hashed.len().saturating_sub(16)..];
            json!({
                "id": format!("external:unknown:{suffix}"),
                "kind": "other-processor",
                "status": "unknown",
                "evidencePaths": [endpoint],
                "targetIds": [],
                "componentIds": [],
                "dataClasses": [],
                "environments": [],
                "credentialsPolicy": "host-owned-unproven",
                "freshnessRequirement": "external-attestation-required",
                "binding": binding,
            })
        })
        .collect();

    let mut all_systems = systems;
    all_systems.extend(unknown);
    all_systems.sort_by(|a, b| {
        a.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(b.get("id").and_then(Value::as_str).unwrap_or_default())
    });

    let component_ids_all: Vec<Value> = components
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.get("id").cloned())
        .collect();

    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-external-system-inventory",
        "systems": all_systems,
        "componentIds": component_ids_all,
        "binding": binding,
    });
    let mut map = value.as_object().cloned().unwrap_or_default();
    map.insert("digest".into(), Value::String(digest(&value)));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_system_requires_core_fields() {
        assert!(external_system(json!({"id": "external:payments"})).is_err());
        assert!(external_system(json!({"id": "e", "kind": "k", "status": "s"})).is_ok());
    }

    #[test]
    fn discover_external_systems_matches_known_dependency() {
        let projection = json!({"dependencies": {"stripe": "1.0.0"}});
        let result = discover_external_systems(&projection, &json!({"components": []}), &Value::Null);
        let systems = result["systems"].as_array().unwrap();
        assert!(systems.iter().any(|s| s["kind"] == "payments"));
    }
}
