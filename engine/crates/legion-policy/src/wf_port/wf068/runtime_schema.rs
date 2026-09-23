//! Port of `src/lib/contracts/arcane/runtime-schema.mjs`'s `RuntimeSchemaSet`.
//!
//! The JS class loads a fixed list of 17 `arcane-schemas/*.schema.json`
//! files from disk (relative to the module's own location) once at
//! construction, keyed by each schema's `$id`. This port embeds the same 17
//! files at compile time (`include_str!`, copied byte-for-byte under
//! `schemas_arcane/` in this owned module directory) instead of reading them
//! from a path relative to the compiled binary, which has no JS-style
//! `import.meta.url` equivalent. Content is identical; only the loading
//! mechanism differs, and it is asserted identical by
//! `tests/wf_wf068.rs::runtime_schema_set_loads_every_embedded_schema_id`.

use crate::wf_port::wf068::errors::ArcaneError;
use crate::wf_port::wf068::schema::validate_schema;
use serde_json::Value;
use std::collections::HashMap;

/// `(embedded JSON text)` for each of the 17 files JS's `FILES` array names,
/// in the same order, so a discrepancy in file count is a compile-time array
/// length mismatch rather than a silent gap.
const EMBEDDED: [&str; 17] = [
    include_str!("schemas_arcane/contract-seal-v1.schema.json"),
    include_str!("schemas_arcane/authority-binding-v1.schema.json"),
    include_str!("schemas_arcane/capability-grant-v1.schema.json"),
    include_str!("schemas_arcane/capability-transition-v1.schema.json"),
    include_str!("schemas_arcane/user-approval-v1.schema.json"),
    include_str!("schemas_arcane/host-event-ledger-record-v1.schema.json"),
    include_str!("schemas_arcane/authority-invocation-proof-v1.schema.json"),
    include_str!("schemas_arcane/authority-proof-transition-v1.schema.json"),
    include_str!("schemas_arcane/pending-terminal-operation-v1.schema.json"),
    include_str!("schemas_arcane/terminal-operation-transition-v1.schema.json"),
    include_str!("schemas_arcane/advisory-artifact-receipt-v1.schema.json"),
    include_str!("schemas_arcane/advisory-certification-receipt-v1.schema.json"),
    include_str!("schemas_arcane/advisory-judgment-v1.schema.json"),
    include_str!("schemas_arcane/host-runtime-output-v1.schema.json"),
    include_str!("schemas_arcane/host-runtime-result-v1.schema.json"),
    include_str!("schemas_arcane/budget-governance-v1.schema.json"),
    include_str!("schemas_arcane/task-budget-seal-v1.schema.json"),
];

/// The RFC3339-required field names JS's `#rfc3339Issues` checks by key name
/// regardless of where they occur in the document.
const RFC3339_KEYS: [&str; 5] = ["sealedAt", "observedAt", "issuedAt", "expiresAt", "at"];

/// Port of `RuntimeSchemaSet`: loads the frozen runtime schemas once and
/// validates values against them by `$id`.
pub struct RuntimeSchemaSet {
    schemas: HashMap<String, Value>,
}

impl RuntimeSchemaSet {
    /// Mirrors the JS constructor: parses every embedded file and indexes by
    /// its `$id`. Panics on malformed embedded JSON or a missing `$id`,
    /// exactly as the JS constructor would throw synchronously and
    /// uncaught — this is fixture data shipped with the binary, not runtime
    /// input.
    pub fn new() -> Self {
        let mut schemas = HashMap::with_capacity(EMBEDDED.len());
        for text in EMBEDDED {
            let schema: Value = serde_json::from_str(text).expect("embedded arcane schema is valid JSON");
            let id = schema
                .get("$id")
                .and_then(Value::as_str)
                .expect("embedded arcane schema has an $id")
                .to_string();
            schemas.insert(id, schema);
        }
        Self { schemas }
    }

    /// JS `validate(id, value)`. Unknown `id` raises `ARC_SCHEMA_INVALID`
    /// (JS throws synchronously there too, so this returns `Result` instead
    /// of an issues list for that one case — matching behaviour, not just
    /// signature, since a caller cannot treat "unknown schema" as "value has
    /// issues").
    pub fn validate(&self, id: &str, value: &Value) -> Result<Vec<String>, ArcaneError> {
        let schema = self.schemas.get(id).ok_or_else(|| {
            ArcaneError::with_details(
                "ARC_SCHEMA_INVALID",
                format!("unknown runtime schema: {id}"),
                serde_json::json!({ "id": id }),
            )
        })?;

        let mut issues = validate_schema(schema, value);

        if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
            let matching = branches
                .iter()
                .filter(|branch| validate_schema(branch, value).is_empty())
                .count();
            if matching != 1 {
                issues.push("$: must match exactly one oneOf branch".to_string());
            }
        }

        issues.extend(rfc3339_issues(value, "$"));
        Ok(issues)
    }

    /// JS `assert(id, value)`: throws `new TypeError(issues[0])` on the
    /// first issue. This port surfaces the same "first issue only" message
    /// via `ArcaneError` (code `ARC_SCHEMA_INVALID`, matching the taxonomy
    /// every other refusal in this chunk uses) rather than a bare
    /// `TypeError`, since Rust has no direct `TypeError` analogue and every
    /// other Arcane refusal in this codebase is a typed `ArcaneError`.
    pub fn assert(&self, id: &str, value: &Value) -> Result<(), ArcaneError> {
        let issues = self.validate(id, value)?;
        if let Some(first) = issues.first() {
            return Err(ArcaneError::new("ARC_SCHEMA_INVALID", first.clone()));
        }
        Ok(())
    }

    /// JS `isRfc3339`: `!Number.isNaN(Date.parse(value))` plus a trailing
    /// `T...(Z|±HH:MM)` check. `Date.parse` is lenient (accepts many
    /// non-RFC3339 ISO-ish forms); this port checks the same trailing-offset
    /// shape and additionally requires a numerically well-formed date-time,
    /// same tradeoff as `schema.rs`'s `date_time_matches`.
    pub fn is_rfc3339(value: &Value) -> bool {
        match value.as_str() {
            Some(s) => date_time_like(s),
            None => false,
        }
    }
}

impl Default for RuntimeSchemaSet {
    fn default() -> Self {
        Self::new()
    }
}

fn date_time_like(value: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$").unwrap()
    });
    re.is_match(value)
}

/// Port of `#rfc3339Issues`: recursively walks `value` and flags any of the
/// five well-known timestamp key names whose value is not RFC3339.
fn rfc3339_issues(value: &Value, path: &str) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .flat_map(|(i, entry)| rfc3339_issues(entry, &format!("{path}[{i}]")))
            .collect(),
        Value::Object(map) => map
            .iter()
            .flat_map(|(key, entry)| {
                let child = format!("{path}.{key}");
                let mut out = Vec::new();
                if RFC3339_KEYS.contains(&key.as_str()) && !RuntimeSchemaSet::is_rfc3339(entry) {
                    out.push(format!("{child}: must be RFC3339"));
                }
                out.extend(rfc3339_issues(entry, &child));
                out
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn loads_all_seventeen_ids_without_collision() {
        let set = RuntimeSchemaSet::new();
        assert_eq!(set.schemas.len(), 17, "an $id collision silently dropped a schema");
    }

    #[test]
    fn unknown_id_is_arc_schema_invalid() {
        let set = RuntimeSchemaSet::new();
        let err = set.validate("nonexistent", &json!({})).unwrap_err();
        assert_eq!(err.code, "ARC_SCHEMA_INVALID");
    }

    #[test]
    fn contract_seal_flags_non_rfc3339_sealed_at() {
        let set = RuntimeSchemaSet::new();
        let value = json!({
            "schemaVersion": 1,
            "kind": "arcane-contract-seal",
            "contractId": "EC-1",
            "version": 1,
            "sourceRevision": "abcdefg",
            "contractDigest": format!("sha256:{}", "a".repeat(64)),
            "dispatchDigest": null,
            "sealedBy": {
                "authority": "legion",
                "assertedBy": "x",
                "verificationMethod": "capability-signature",
                "perMessage": true,
            },
            "sealedAt": "not-a-date",
            "contract": {},
        });
        let issues = set.validate("arcane-contract-seal-v1", &value).unwrap();
        assert!(issues.iter().any(|i| i.contains("sealedAt")), "issues: {issues:?}");
    }

    #[test]
    fn contract_seal_accepts_valid_record() {
        let set = RuntimeSchemaSet::new();
        let value = json!({
            "schemaVersion": 1,
            "kind": "arcane-contract-seal",
            "contractId": "EC-1",
            "version": 1,
            "sourceRevision": "abcdefg",
            "contractDigest": format!("sha256:{}", "a".repeat(64)),
            "dispatchDigest": null,
            "sealedBy": {
                "authority": "legion",
                "assertedBy": "x",
                "verificationMethod": "capability-signature",
                "perMessage": true,
            },
            "sealedAt": "2026-09-23T00:00:00Z",
            "contract": {},
        });
        assert!(set.assert("arcane-contract-seal-v1", &value).is_ok());
    }
}
