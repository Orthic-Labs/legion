//! Port of `scripts/generate-schemas.mjs`.
//!
//! Generates the three committed JSON schemas from the code-owned contract
//! enums in `legion_contracts::enums` so runtime validators and generated
//! JSON schemas can never drift. `--check` fails when a committed schema
//! differs from what the enums generate; without `--check` it (re)writes
//! each schema and prints `wrote <path>`.

use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use legion_contracts::enums::{EVIDENCE_STRENGTH, FACT_KINDS, PROVIDER_STATUS, SECURITY_VERDICTS};

fn enum_arr(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|s| Value::from(*s)).collect())
}

pub fn build_provider_result_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/audit-provider-result-v1.json",
        "type": "object",
        "additionalProperties": false,
        "required": ["schemaVersion", "provider", "applicable", "required", "status", "complete", "coverage", "candidates", "findings", "coverageGaps", "degradation"],
        "properties": {
            "schemaVersion": { "const": 1 },
            "provider": { "type": "string", "minLength": 1 },
            "applicable": { "type": "boolean" },
            "required": { "type": "boolean" },
            "status": { "enum": enum_arr(PROVIDER_STATUS) },
            "complete": { "type": "boolean" },
            "coverage": {
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "denominatorDigest": { "type": "string", "pattern": "^sha256:([a-f0-9]{64}|unbound)$" },
                    "expected": { "type": "integer", "minimum": 0 },
                    "examined": { "type": "integer", "minimum": 0 },
                    "unexamined": { "type": "integer", "minimum": 0 },
                }
            },
            "candidates": { "type": "array" },
            "findings": { "type": "array" },
            "coverageGaps": { "type": "array" },
            "degradation": { "type": "array" },
            "receipts": { "type": "array" },
            "artifacts": { "type": "array" },
            "commands": { "type": "array" },
            "inventory": { "type": ["array", "object"] },
            "phase": { "type": "string" },
            "details": {
                "type": "object",
                "additionalProperties": false,
                "required": ["family", "componentIds", "limitations", "rawArtifacts"],
                "properties": {
                    "family": { "type": "string", "minLength": 1 },
                    "componentIds": { "type": "array", "items": { "type": "string" } },
                    "limitations": { "type": "array" },
                    "rawArtifacts": { "type": "array" },
                }
            },
        }
    })
}

pub fn build_security_verdict_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/security-verdict-v1.json",
        "title": "SecurityVerdictV1",
        "type": "object",
        "required": ["schemaVersion", "kind", "candidateId", "candidateProvider", "adjudicatorProvider", "adjudicatorContextId", "evidenceStrength", "verdict", "threatModel", "reachability", "impact", "variantAnalysisRequired"],
        "properties": {
            "schemaVersion": { "const": 1 },
            "kind": { "const": "security-verdict" },
            "candidateId": { "type": "string" },
            "candidateProvider": { "type": "string" },
            "adjudicatorProvider": { "type": "string" },
            "adjudicatorContextId": { "type": "string" },
            "evidenceStrength": { "enum": enum_arr(EVIDENCE_STRENGTH) },
            "verdict": { "enum": enum_arr(SECURITY_VERDICTS) },
            "severity": { "type": ["string", "null"], "enum": ["critical", "high", "medium", "low", null] },
            "threatModel": { "type": "string" },
            "attackerControl": { "type": "string" },
            "reachability": { "type": "string" },
            "trustBoundaries": { "type": "array", "items": { "type": "string" } },
            "impact": { "type": "string" },
            "proof": { "type": ["object", "null"] },
            "variantAnalysisRequired": { "type": "boolean" },
            "verdictDigest": { "type": "string", "pattern": "^sha256:" },
        },
        "additionalProperties": true,
    })
}

pub fn build_web_actor_fixture_schema() -> Value {
    let nonempty = json!({ "type": "string", "minLength": 1 });
    let binding_keys = [
        "targetId", "environment", "actorId", "tenantId", "browser", "browserVersion",
        "viewport", "locale", "sourceRevision", "artifactDigest",
    ];
    let mut binding_properties = serde_json::Map::new();
    for key in binding_keys {
        binding_properties.insert(key.to_string(), nonempty.clone());
    }

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/platform/web-actor-fixture-v1.json",
        "type": "object",
        "additionalProperties": false,
        "required": ["schemaVersion", "kind", "status", "complete", "proof", "terminal", "binding", "actors", "denominator", "coverageGaps", "digest"],
        "properties": {
            "schemaVersion": { "const": 1 },
            "kind": { "const": "legion-web-actor-fixtures" },
            "status": { "const": "pass" },
            "complete": { "const": true },
            "proof": { "const": true },
            "terminal": { "const": true },
            "binding": {
                "type": "object",
                "additionalProperties": false,
                "required": binding_keys,
                "properties": Value::Object(binding_properties),
            },
            "actors": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/actor" } },
            "denominator": {
                "type": "object",
                "additionalProperties": false,
                "required": ["total", "accounted", "receipts", "omitted", "missing", "expectedIds"],
                "properties": {
                    "total": { "type": "integer", "minimum": 1 },
                    "accounted": { "type": "integer", "minimum": 1 },
                    "receipts": { "type": "integer", "minimum": 1 },
                    "omitted": { "const": 0 },
                    "missing": { "type": "array", "maxItems": 0, "items": nonempty.clone() },
                    "expectedIds": { "type": "array", "minItems": 1, "items": nonempty.clone() },
                }
            },
            "coverageGaps": { "type": "array", "maxItems": 0, "items": nonempty.clone() },
            "digest": { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
        },
        "$defs": {
            "credentialReference": {
                "type": "object",
                "required": ["type", "id"],
                "additionalProperties": false,
                "properties": {
                    "type": { "enum": ["env", "keychain", "secret-manager", "vault"] },
                    "id": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]*$" },
                }
            },
            "transitionCapability": {
                "type": "object",
                "required": ["id", "toActorId", "fromTenantId", "toTenantId", "authorizationId"],
                "additionalProperties": false,
                "properties": {
                    "id": nonempty,
                    "toActorId": { "type": "string", "minLength": 1 },
                    "fromTenantId": { "type": "string", "minLength": 1 },
                    "toTenantId": { "type": "string", "minLength": 1 },
                    "authorizationId": { "type": "string", "minLength": 1 },
                }
            },
            "actor": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "identityId", "credentialPolicyId", "sessionPolicyId", "role", "tier", "tenantId", "accountState", "credential", "issuedAt", "expiresAt", "revokedAt", "serverAuthorizations", "uiVisibility", "transitionCapabilities", "concurrencyKey"],
                "properties": {
                    "id": { "type": "string", "minLength": 1 },
                    "identityId": { "type": "string", "minLength": 1 },
                    "credentialPolicyId": { "type": "string", "minLength": 1 },
                    "sessionPolicyId": { "type": "string", "minLength": 1 },
                    "role": { "type": "string", "minLength": 1 },
                    "tier": { "type": "string", "minLength": 1 },
                    "tenantId": { "type": "string", "minLength": 1 },
                    "accountState": { "enum": ["active", "disabled", "expired", "locked", "revoked"] },
                    "credential": { "$ref": "#/$defs/credentialReference" },
                    "issuedAt": { "type": ["string", "null"] },
                    "expiresAt": { "type": ["string", "null"] },
                    "revokedAt": { "type": ["string", "null"] },
                    "serverAuthorizations": { "type": "array", "items": { "type": "string", "minLength": 1 } },
                    "uiVisibility": { "type": "array", "items": { "type": "string", "minLength": 1 } },
                    "transitionCapabilities": { "type": "array", "items": { "$ref": "#/$defs/transitionCapability" } },
                    "concurrencyKey": { "type": "string", "minLength": 1 },
                }
            },
        }
    })
}

/// (relative path, schema value) pairs, in `buildSchemas()`'s iteration order.
pub fn build_schemas() -> Vec<(&'static str, Value)> {
    vec![
        ("src/schemas/provider-result-v1.schema.json", build_provider_result_schema()),
        ("src/schemas/security-verdict-v1.schema.json", build_security_verdict_schema()),
        ("src/schemas/platform/web-actor-fixture-v1.schema.json", build_web_actor_fixture_schema()),
    ]
}

fn render(value: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(value).unwrap())
}

/// `legion-dev generate-schemas [--check]`
pub fn run(root: &Path, check: bool) -> bool {
    let mut failed = false;
    for (rel, value) in build_schemas() {
        let generated = render(&value);
        let path = root.join(rel);
        let committed = fs::read_to_string(&path).unwrap_or_default();
        if committed != generated {
            if check {
                eprintln!(
                    "SCHEMA DRIFT: {rel} is not up to date with the code-owned enums; run node scripts/generate-schemas.mjs"
                );
                failed = true;
            } else {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Err(e) = fs::write(&path, &generated) {
                    eprintln!("generate-schemas: {rel}: {e}");
                    failed = true;
                    continue;
                }
                println!("wrote {rel}");
            }
        } else if check {
            println!("OK {rel}");
        }
    }

    if check {
        if failed {
            return false;
        }
        println!("schemas are in sync with contracts");
    }
    !failed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_result_schema_has_expected_status_enum() {
        let schema = build_provider_result_schema();
        assert_eq!(
            schema["properties"]["status"]["enum"].as_array().unwrap().len(),
            PROVIDER_STATUS.len()
        );
    }
}
