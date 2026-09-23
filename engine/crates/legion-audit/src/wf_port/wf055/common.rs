//! Port of `src/providers/security/model-extractors/common.mjs`'s entity /
//! relation / fact / control-entity constructors (the shared builders this
//! chunk's three extractors — `identity.mjs`, `mobile.mjs`,
//! `native-workspace.mjs` — depend on).
//!
//! `extractCommon` (repository-artifact / package-manifest extraction) is
//! not part of this chunk's owned file list and is not ported here.
//!
//! Records are `serde_json::Value`, matching the wf052 `contracts.rs`
//! precedent: `stable_id`/`digest` are reused from there unchanged (both
//! are pure functions over already-canonicalized JSON, so re-implementing
//! them here would risk drift from the one canonical port).

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

use crate::wf_port::wf052::contracts::stable_id;

/// `[...new Set(evidenceRefs ?? [])].sort()`
fn dedup_sorted(evidence_refs: &[String]) -> Vec<Value> {
    let set: BTreeSet<&String> = evidence_refs.iter().collect();
    set.into_iter().map(|s| Value::String(s.clone())).collect()
}

/// Port of `entity(kind, name, attributes, evidenceRefs, options = {})`.
///
/// `assertion` defaults to `"observed"`, `evidence_strength` to
/// `"verified"`, matching the JS `options.assertion ?? 'observed'` /
/// `options.evidenceStrength ?? 'verified'`.
pub fn entity(
    kind: &str,
    name: &str,
    attributes: Value,
    evidence_refs: &[String],
    assertion: Option<&str>,
    evidence_strength: Option<&str>,
) -> Value {
    let mut body = Map::new();
    body.insert("kind".into(), Value::String(kind.into()));
    body.insert("name".into(), Value::String(name.into()));
    body.insert(
        "attributes".into(),
        if attributes.is_null() { json!({}) } else { attributes },
    );
    body.insert(
        "assertion".into(),
        Value::String(assertion.unwrap_or("observed").into()),
    );
    body.insert(
        "evidenceStrength".into(),
        Value::String(evidence_strength.unwrap_or("verified").into()),
    );
    body.insert("evidenceRefs".into(), Value::Array(dedup_sorted(evidence_refs)));

    let body_value = Value::Object(body.clone());
    let id = stable_id("security-model-entity", &body_value);
    body.insert("id".into(), Value::String(id));
    Value::Object(body)
}

/// Port of `relation(kind, from, to, evidenceRefs, attributes = {}, options = {})`.
pub fn relation(
    kind: &str,
    from: &str,
    to: &str,
    evidence_refs: &[String],
    attributes: Value,
    assertion: Option<&str>,
    evidence_strength: Option<&str>,
) -> Value {
    let mut body = Map::new();
    body.insert("kind".into(), Value::String(kind.into()));
    body.insert("from".into(), Value::String(from.into()));
    body.insert("to".into(), Value::String(to.into()));
    body.insert(
        "attributes".into(),
        if attributes.is_null() { json!({}) } else { attributes },
    );
    body.insert(
        "assertion".into(),
        Value::String(assertion.unwrap_or("observed").into()),
    );
    body.insert(
        "evidenceStrength".into(),
        Value::String(evidence_strength.unwrap_or("verified").into()),
    );
    body.insert("evidenceRefs".into(), Value::Array(dedup_sorted(evidence_refs)));

    let body_value = Value::Object(body.clone());
    let id = stable_id("security-model-relation", &body_value);
    body.insert("id".into(), Value::String(id));
    Value::Object(body)
}

/// Fields accepted by [`fact`], mirroring the JS `fields` object's optional
/// keys (`subject`/`action`/`object`/`scope`/`environment`/`tenant`/`attributes`,
/// each `?? null` / `?? {}`).
#[derive(Default, Clone)]
pub struct FactFields {
    pub subject: Option<String>,
    pub action: Option<String>,
    pub object: Option<String>,
    pub scope: Option<String>,
    pub environment: Option<String>,
    pub tenant: Option<String>,
    pub attributes: Option<Value>,
}

fn opt_string(value: &Option<String>) -> Value {
    match value {
        Some(s) => Value::String(s.clone()),
        None => Value::Null,
    }
}

/// Port of `fact(kind, fields, evidenceRefs = [])`.
pub fn fact(kind: &str, fields: FactFields, evidence_refs: &[String]) -> Value {
    let mut body = Map::new();
    body.insert("kind".into(), Value::String(kind.into()));
    body.insert("subject".into(), opt_string(&fields.subject));
    body.insert("action".into(), opt_string(&fields.action));
    body.insert("object".into(), opt_string(&fields.object));
    body.insert("scope".into(), opt_string(&fields.scope));
    body.insert("environment".into(), opt_string(&fields.environment));
    body.insert("tenant".into(), opt_string(&fields.tenant));
    body.insert(
        "attributes".into(),
        fields.attributes.unwrap_or_else(|| json!({})),
    );
    body.insert("evidenceRefs".into(), Value::Array(dedup_sorted(evidence_refs)));

    let body_value = Value::Object(body.clone());
    let id = stable_id("security-fact", &body_value);
    body.insert("id".into(), Value::String(id));
    Value::Object(body)
}

/// Port of `controlEntity(controlType, name, evidenceRefs, attributes = {})`.
pub fn control_entity(
    control_type: &str,
    name: &str,
    evidence_refs: &[String],
    attributes: Value,
) -> Value {
    let mut merged = match attributes {
        Value::Object(map) => map,
        Value::Null => Map::new(),
        other => {
            // JS spreads non-object attributes as a no-op; mirror by ignoring.
            let _ = other;
            Map::new()
        }
    };
    merged.insert("controlType".into(), Value::String(control_type.into()));
    entity("control", name, Value::Object(merged), evidence_refs, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_id_is_deterministic_and_evidence_refs_are_deduped_and_sorted() {
        let e1 = entity(
            "control",
            "auth control x",
            json!({"controlType": "authentication"}),
            &["b".to_string(), "a".to_string(), "a".to_string()],
            None,
            None,
        );
        let e2 = entity(
            "control",
            "auth control x",
            json!({"controlType": "authentication"}),
            &["a".to_string(), "b".to_string()],
            None,
            None,
        );
        assert_eq!(e1["id"], e2["id"]);
        assert_eq!(e1["evidenceRefs"], json!(["a", "b"]));
        assert_eq!(e1["assertion"], "observed");
        assert_eq!(e1["evidenceStrength"], "verified");
    }

    #[test]
    fn control_entity_merges_control_type_into_attributes() {
        let c = control_entity("data-backup", "backup policy", &[], json!({"controlState": "absent"}));
        assert_eq!(c["kind"], "control");
        assert_eq!(c["attributes"]["controlType"], "data-backup");
        assert_eq!(c["attributes"]["controlState"], "absent");
    }

    #[test]
    fn fact_defaults_missing_fields_to_null_and_empty_attributes() {
        let f = fact(
            "network-reachability",
            FactFields {
                subject: Some("actor:external".into()),
                action: Some("reach".into()),
                object: Some("entrypoint-1".into()),
                scope: Some("mobile".into()),
                ..Default::default()
            },
            &[],
        );
        assert_eq!(f["kind"], "network-reachability");
        assert_eq!(f["environment"], Value::Null);
        assert_eq!(f["tenant"], Value::Null);
        assert_eq!(f["attributes"], json!({}));
    }
}
