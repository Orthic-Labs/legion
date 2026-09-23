//! Port of `src/lib/inventory/release-contract/**`.
//!
//! `loadReleaseContract` (`load.mjs`) reads a JSON file from disk before
//! delegating to `mergeReleaseContract`; that file I/O is ported as
//! `load_release_contract` here using `std::fs::read_to_string`.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::binding::digest;
use super::error::InventoryError;

type R<T> = Result<T, InventoryError>;

/// Port of `contractConflicts`.
pub fn contract_conflicts(contract: &Value) -> Vec<Value> {
    contract
        .get("conflicts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|field| json!({"field": field, "status": "conflict"}))
        .collect()
}

const HOST_OWNED: &[&str] = &[
    "signingAuthority",
    "productionAccess",
    "rights",
    "riskAcceptance",
    "hostCapabilities",
    "legalConclusion",
];

const ALLOWED: &[&str] = &[
    "schemaVersion",
    "claimLevel",
    "platforms",
    "versions",
    "architectures",
    "browsers",
    "devices",
    "installModes",
    "environments",
    "roles",
    "tenants",
    "plans",
    "entitlements",
    "criticalJourneys",
    "dataClasses",
    "assets",
    "budgets",
    "unsupportedScenarios",
    "riskAuthority",
    "exactReleaseCandidates",
    "policyFlags",
];

fn required_for(level: &str) -> &'static [&'static str] {
    match level {
        "runtime" => &["platforms"],
        "product" => &["platforms", "environments", "criticalJourneys"],
        "release" => &["platforms", "environments", "criticalJourneys", "exactReleaseCandidates"],
        _ => &[],
    }
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut canon: Vec<Value> = items.iter().map(canonical).collect();
            canon.sort_by(|a, b| serde_json::to_string(a).unwrap_or_default().cmp(&serde_json::to_string(b).unwrap_or_default()));
            Value::Array(canon)
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonical(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn validate(source: &Value, label: &str) -> R<()> {
    if let Value::Object(map) = source {
        for key in map.keys() {
            if HOST_OWNED.contains(&key.as_str()) {
                return Err(InventoryError::new(format!("host-owned field: {key}")));
            }
            if !ALLOWED.contains(&key.as_str()) {
                return Err(InventoryError::new(format!("unknown release contract field: {label}.{key}")));
            }
        }
    }
    Ok(())
}

/// Port of `mergeReleaseContract`.
pub fn merge_release_contract(
    observed: Value,
    declared: Value,
    policy: Value,
    external_evidence: Value,
    binding: Value,
) -> R<Value> {
    validate(&observed, "observed")?;
    validate(&declared, "declared")?;
    validate(&policy, "policy")?;

    let has_external_keys = external_evidence
        .as_object()
        .map(|m| !m.is_empty())
        .unwrap_or(false);
    if has_external_keys {
        let ext_binding = external_evidence.get("binding").cloned();
        let binding_matches = ext_binding
            .as_ref()
            .map(|b| serde_json::to_string(&canonical(b)).unwrap_or_default() == serde_json::to_string(&canonical(&binding)).unwrap_or_default())
            .unwrap_or(false);
        if ext_binding.is_none() || !binding_matches {
            return Err(InventoryError::new("external release evidence binding mismatch"));
        }
    }

    let normalized_observed = canonical(&observed);
    let normalized_declared = canonical(&declared);
    let normalized_policy = canonical(&policy);
    let normalized_external = canonical(&external_evidence);

    let declared_keys: Vec<String> = normalized_declared
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let conflicts: Vec<Value> = declared_keys
        .iter()
        .filter(|key| {
            let observed_val = normalized_observed.get(key.as_str());
            let declared_val = normalized_declared.get(key.as_str());
            observed_val.is_some()
                && observed_val != Some(&Value::Null)
                && serde_json::to_string(observed_val.unwrap()).unwrap_or_default()
                    != serde_json::to_string(declared_val.unwrap()).unwrap_or_default()
        })
        .cloned()
        .map(Value::String)
        .collect();

    let level = declared
        .get("claimLevel")
        .or_else(|| observed.get("claimLevel"))
        .and_then(Value::as_str)
        .unwrap_or("source")
        .to_string();

    let mut effective = observed.as_object().cloned().unwrap_or_default();
    if let Some(d) = declared.as_object() {
        for (k, v) in d {
            effective.insert(k.clone(), v.clone());
        }
    }
    let effective = Value::Object(effective);

    let missing: Vec<Value> = required_for(&level)
        .iter()
        .filter(|key| {
            let v = effective.get(**key);
            match v {
                None => true,
                Some(Value::Null) => true,
                Some(Value::Array(a)) => a.is_empty(),
                _ => false,
            }
        })
        .map(|k| Value::String(k.to_string()))
        .collect();

    let get_arr = |key: &str| -> Value { effective.get(key).cloned().unwrap_or_else(|| json!([])) };
    let plans = get_arr("plans");
    let entitlements = get_arr("entitlements");
    let mut plans_and_entitlements: Vec<Value> = plans.as_array().cloned().unwrap_or_default();
    plans_and_entitlements.extend(entitlements.as_array().cloned().unwrap_or_default());

    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-release-contract",
        "observed": normalized_observed,
        "declared": normalized_declared,
        "policy": normalized_policy,
        "externalEvidence": normalized_external,
        "conflicts": conflicts,
        "missing": missing,
        "claimLevel": level,
        "requestedClaimLevel": level,
        "targetIds": get_arr("targetIds"),
        "supportedPlatforms": get_arr("platforms"),
        "supportedVersions": get_arr("versions"),
        "architectures": get_arr("architectures"),
        "browsers": get_arr("browsers"),
        "devices": get_arr("devices"),
        "installationModes": get_arr("installModes"),
        "environments": get_arr("environments"),
        "roles": get_arr("roles"),
        "tenants": get_arr("tenants"),
        "plansAndEntitlements": plans_and_entitlements,
        "criticalJourneyIds": get_arr("criticalJourneys"),
        "dataClasses": get_arr("dataClasses"),
        "crownJewelAssets": get_arr("assets"),
        "budgets": effective.get("budgets").cloned().unwrap_or_else(|| json!({})),
        "unsupportedScenarios": get_arr("unsupportedScenarios"),
        "acceptedRiskAuthority": policy.get("riskAuthority").cloned().unwrap_or(Value::Null),
        "releaseCandidates": get_arr("exactReleaseCandidates"),
        "observedDeclaredConflicts": conflicts.clone(),
        "missingDeclarations": missing.clone(),
        "binding": binding,
    });
    let mut map = value.as_object().cloned().unwrap_or_default();
    map.insert("digest".into(), Value::String(digest(&value)));
    Ok(Value::Object(map))
}

/// Port of `loadReleaseContract`. `path` is optional, matching the JS
/// `path ? readFile(...) : {}` branch.
pub fn load_release_contract(
    path: Option<&Path>,
    observed: Value,
    policy: Value,
    external_evidence: Value,
    binding: Value,
) -> R<Value> {
    let declared: Value = match path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|error| InventoryError::new(format!("could not read release contract: {error}")))?;
            serde_json::from_str(&text)
                .map_err(|error| InventoryError::new(format!("invalid release contract JSON: {error}")))?
        }
        None => json!({}),
    };
    if let Some(schema_version) = declared.get("schemaVersion") {
        if schema_version != &Value::Null && schema_version != &json!(1) {
            return Err(InventoryError::new("unsupported release contract version"));
        }
    }
    merge_release_contract(observed, declared, policy, external_evidence, binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_conflicts_maps_fields() {
        let contract = json!({"conflicts": ["platforms"]});
        let result = contract_conflicts(&contract);
        assert_eq!(result, vec![json!({"field": "platforms", "status": "conflict"})]);
    }

    #[test]
    fn merge_release_contract_rejects_unknown_field() {
        let result = merge_release_contract(json!({"bogus": true}), json!({}), json!({}), json!({}), Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn merge_release_contract_reports_missing_required_fields_for_product_level() {
        let observed = json!({"claimLevel": "product"});
        let result = merge_release_contract(observed, json!({}), json!({}), json!({}), Value::Null).unwrap();
        let missing: Vec<String> = result["missing"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(missing.contains(&"platforms".to_string()));
    }
}
