//! Port of `src/lib/providers/sdk/contracts.mjs`.
//!
//! `contracts.mjs` imports `PROVIDER_ROLE`, `assertEnum`, and
//! `assertSchemaVersion` from `../../contracts/enums.mjs` (not in this
//! chunk). `PROVIDER_ROLE` there is
//! `['deterministic', 'candidate-generator', 'adjudicator', 'variant-analysis', 'renderer']`
//! — a materially different, shorter set than `dag.mjs`'s
//! `ROLE_OUTPUT_AUTHORITY` keys (`model-builder`, `hypothesis-generator`,
//! `variant-analyzer` vs `variant-analysis`, `evidence-synthesizer`). That
//! mismatch is present in the JS source as-is; this port does not correct
//! it.

use serde_json::Value;

use super::SdkError;

/// Mirrors `enums.mjs`'s `PROVIDER_ROLE`.
pub const PROVIDER_ROLE: &[&str] = &[
    "deterministic",
    "candidate-generator",
    "adjudicator",
    "variant-analysis",
    "renderer",
];

const REQUIRED: &[&str] = &[
    "id",
    "providerVersion",
    "family",
    "lensIds",
    "role",
    "phase",
    "dependsOn",
    "consumes",
    "produces",
    "selector",
    "denominatorKind",
    "runner",
    "hostCapabilities",
    "execution",
    "reasoning",
    "benchmark",
    "cleanClaim",
    "controlIds",
    "scopes",
    "selectable",
];

const PHASES: &[&str] = &[
    "inventory", "source", "runtime", "product", "release", "facts", "judgment", "render",
];

const RUNNERS: &[&str] = &[
    "planned",
    "legacy-check",
    "runtime-script",
    "security-pack",
    "external-process",
    "imported-artifact",
    "reasoning-contract",
    "renderer",
];

const EXECUTION_KEYS: &[&str] = &[
    "scheduleClass",
    "resourceClaims",
    "concurrencyKey",
    "maxParallelism",
    "orderSensitive",
    "interruptible",
    "cachePolicy",
    "failurePolicy",
];

const REASONING_KEYS: &[&str] = &["requirement", "trigger", "subjectKind", "freshContext", "producerSeparation"];

const BENCHMARK_KEYS: &[&str] = &["status", "requiredForCleanClaim", "qualificationDigest"];

fn is_null(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

fn is_array(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(_)))
}

fn provider_id(provider: &Value) -> String {
    provider
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| "<unknown>".to_owned())
}

fn assert_enum(label: &str, values: &[&str], value: Option<&str>) -> Result<(), SdkError> {
    let value = value.unwrap_or("");
    if !values.contains(&value) {
        return Err(SdkError::new(format!("unknown {label}: {value}")));
    }
    Ok(())
}

fn assert_schema_version(label: &str, version: Option<i64>, supported: &[i64]) -> Result<(), SdkError> {
    let version = version.unwrap_or(-1);
    if !supported.contains(&version) {
        return Err(SdkError::new(format!("{label} unsupported schema version: {version}")));
    }
    Ok(())
}

/// Faithful port of `validateProviderV2`.
pub fn validate_provider_v2(provider: &Value) -> Result<Value, SdkError> {
    let schema_version = provider.get("schemaVersion").and_then(Value::as_i64);
    assert_schema_version("provider", schema_version, &[2])?;

    let id = provider_id(provider);
    let object = provider
        .as_object()
        .ok_or_else(|| SdkError::new(format!("provider {id} unknown field <non-object>")))?;

    for key in object.keys() {
        if key != "schemaVersion" && !REQUIRED.contains(&key.as_str()) {
            return Err(SdkError::new(format!("provider {id} unknown field {key}")));
        }
    }
    for key in REQUIRED {
        if is_null(object.get(*key)) {
            return Err(SdkError::new(format!("provider {id} missing {key}")));
        }
    }

    assert_enum("provider role", PROVIDER_ROLE, provider.get("role").and_then(Value::as_str))?;

    let phase = provider.get("phase").and_then(Value::as_str).unwrap_or("");
    if !PHASES.contains(&phase) {
        return Err(SdkError::new(format!("provider {id} invalid phase")));
    }

    let runner_kind = provider.pointer("/runner/kind").and_then(Value::as_str).unwrap_or("");
    if !RUNNERS.contains(&runner_kind) {
        return Err(SdkError::new(format!("provider {id} invalid runner")));
    }

    for field in ["lensIds", "dependsOn", "consumes", "produces", "hostCapabilities", "controlIds", "scopes"] {
        if !is_array(object.get(field)) {
            return Err(SdkError::new(format!("provider {id} {field} must be array")));
        }
    }

    if let Some(claims) = provider.pointer("/execution/resourceClaims").and_then(Value::as_object) {
        for (name, amount) in claims {
            let finite_non_negative = amount.as_f64().map(|value| value.is_finite() && value >= 0.0).unwrap_or(false);
            if !finite_non_negative {
                return Err(SdkError::new(format!("provider {id} invalid resource {name}")));
            }
        }
    }

    if let Some(execution) = provider.get("execution").and_then(Value::as_object) {
        for key in execution.keys() {
            if !EXECUTION_KEYS.contains(&key.as_str()) {
                return Err(SdkError::new(format!("provider {id} unknown execution field {key}")));
            }
        }
    }
    if let Some(reasoning) = provider.get("reasoning").and_then(Value::as_object) {
        for key in reasoning.keys() {
            if !REASONING_KEYS.contains(&key.as_str()) {
                return Err(SdkError::new(format!("provider {id} unknown reasoning field {key}")));
            }
        }
    }
    if let Some(benchmark) = provider.get("benchmark").and_then(Value::as_object) {
        for key in benchmark.keys() {
            if !BENCHMARK_KEYS.contains(&key.as_str()) {
                return Err(SdkError::new(format!("provider {id} unknown benchmark field {key}")));
            }
        }
    }

    if runner_kind == "runtime-script" {
        let module = provider.pointer("/runner/module").and_then(Value::as_str);
        let module_digest = provider.pointer("/runner/moduleDigest").and_then(Value::as_str).unwrap_or("");
        let digest_ok = module_digest.len() == 71
            && module_digest.starts_with("sha256:")
            && module_digest[7..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if module.map(str::is_empty).unwrap_or(true) || module.is_none() || !digest_ok {
            return Err(SdkError::new(format!("provider {id} runtime module must be digest sealed")));
        }
    }

    let selectable = provider.get("selectable").and_then(Value::as_bool).unwrap_or(false);
    if runner_kind == "planned" && selectable {
        return Err(SdkError::new(format!("provider {id} planned provider must be unselectable")));
    }

    if selectable {
        let control_ids = string_array(provider, "controlIds");
        let scopes = string_array(provider, "scopes");
        if control_ids.is_empty() || scopes.is_empty() {
            return Err(SdkError::new(format!("provider {id} selectable provider requires controls and scopes")));
        }
    }

    Ok(provider.clone())
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// Faithful port of `validateProviderOutputAuthority`.
pub fn validate_provider_output_authority(provider: &Value, result: &Value) -> Result<Value, SdkError> {
    let role = provider.get("role").and_then(Value::as_str).unwrap_or("");
    let findings_len = result.get("findings").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    if role == "candidate-generator" && findings_len > 0 {
        return Err(SdkError::new("candidate-generator cannot emit findings"));
    }
    Ok(result.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_provider() -> Value {
        json!({
            "schemaVersion": 2,
            "id": "p1",
            "providerVersion": "1.0.0",
            "family": "security",
            "lensIds": [],
            "role": "deterministic",
            "phase": "runtime",
            "dependsOn": [],
            "consumes": [],
            "produces": [],
            "selector": {},
            "denominatorKind": "paths",
            "runner": {"kind": "legacy-check"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {},
            "cleanClaim": "none",
            "controlIds": [],
            "scopes": [],
            "selectable": false,
        })
    }

    #[test]
    fn valid_provider_passes() {
        assert!(validate_provider_v2(&valid_provider()).is_ok());
    }

    #[test]
    fn wrong_schema_version_is_rejected() {
        let mut provider = valid_provider();
        provider["schemaVersion"] = json!(1);
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("unsupported schema version"), "{}", err.0);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let mut provider = valid_provider();
        provider["extra"] = json!(true);
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("unknown field extra"), "{}", err.0);
    }

    #[test]
    fn missing_required_field_is_rejected() {
        let mut provider = valid_provider();
        provider.as_object_mut().unwrap().remove("cleanClaim");
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("missing cleanClaim"), "{}", err.0);
    }

    #[test]
    fn invalid_role_is_rejected() {
        let mut provider = valid_provider();
        provider["role"] = json!("not-a-role");
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("unknown provider role"), "{}", err.0);
    }

    #[test]
    fn invalid_phase_is_rejected() {
        let mut provider = valid_provider();
        provider["phase"] = json!("not-a-phase");
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("invalid phase"), "{}", err.0);
    }

    #[test]
    fn invalid_runner_is_rejected() {
        let mut provider = valid_provider();
        provider["runner"] = json!({"kind": "not-a-runner"});
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("invalid runner"), "{}", err.0);
    }

    #[test]
    fn runtime_script_requires_digest_sealed_module() {
        let mut provider = valid_provider();
        provider["runner"] = json!({"kind": "runtime-script", "module": "mod"});
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("digest sealed"), "{}", err.0);

        provider["runner"] = json!({
            "kind": "runtime-script",
            "module": "mod",
            "moduleDigest": format!("sha256:{}", "a".repeat(64)),
        });
        assert!(validate_provider_v2(&provider).is_ok());
    }

    #[test]
    fn planned_provider_must_be_unselectable() {
        let mut provider = valid_provider();
        provider["runner"] = json!({"kind": "planned"});
        provider["selectable"] = json!(true);
        provider["controlIds"] = json!(["c1"]);
        provider["scopes"] = json!(["s1"]);
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("must be unselectable"), "{}", err.0);
    }

    #[test]
    fn selectable_provider_requires_controls_and_scopes() {
        let mut provider = valid_provider();
        provider["selectable"] = json!(true);
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("requires controls and scopes"), "{}", err.0);

        provider["controlIds"] = json!(["c1"]);
        provider["scopes"] = json!(["s1"]);
        assert!(validate_provider_v2(&provider).is_ok());
    }

    #[test]
    fn negative_resource_claim_is_rejected() {
        let mut provider = valid_provider();
        provider["execution"] = json!({"resourceClaims": {"cpu": -1}});
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("invalid resource cpu"), "{}", err.0);
    }

    #[test]
    fn unknown_execution_field_is_rejected() {
        let mut provider = valid_provider();
        provider["execution"] = json!({"notAField": true});
        let err = validate_provider_v2(&provider).unwrap_err();
        assert!(err.0.contains("unknown execution field"), "{}", err.0);
    }

    #[test]
    fn candidate_generator_cannot_emit_findings() {
        let provider = json!({"role": "candidate-generator"});
        let result = json!({"findings": [{"id": "f1"}]});
        let err = validate_provider_output_authority(&provider, &result).unwrap_err();
        assert_eq!(err.0, "candidate-generator cannot emit findings");
    }

    #[test]
    fn non_candidate_generator_may_emit_findings() {
        let provider = json!({"role": "deterministic"});
        let result = json!({"findings": [{"id": "f1"}]});
        assert!(validate_provider_output_authority(&provider, &result).is_ok());
    }
}
