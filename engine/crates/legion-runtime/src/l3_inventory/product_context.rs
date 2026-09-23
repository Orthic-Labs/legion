//! Port of `src/lib/inventory/product-context/**`.

use std::collections::BTreeSet;

use serde_json::{json, Value};

fn str_set(a: &Value, key: &str, b: &Value, sub_key: &str) -> Vec<Value> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for v in a.get(key).and_then(Value::as_array).cloned().unwrap_or_default() {
        if let Some(s) = v.as_str() {
            set.insert(s.to_string());
        }
    }
    if let Some(declared) = b.get("declared") {
        for v in declared
            .get(sub_key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(s) = v.as_str() {
                set.insert(s.to_string());
            }
        }
    }
    set.into_iter().map(Value::String).collect()
}

/// Port of `extractActors`.
pub fn extract_actors(projection: &Value, contract: &Value) -> Value {
    json!({
        "roles": str_set(projection, "roles", contract, "roles"),
        "tenants": str_set(projection, "tenants", contract, "tenants"),
    })
}

/// Port of `extractDataContext`.
pub fn extract_data_context(projection: &Value, contract: &Value) -> Value {
    json!({
        "dataClasses": str_set(projection, "dataClasses", contract, "dataClasses"),
        "assets": projection.get("assets").cloned().unwrap_or_else(|| json!([])),
    })
}

/// Port of `extractRiskContext`.
pub fn extract_risk_context(projection: &Value, contract: &Value) -> Value {
    json!({
        "candidates": projection.get("riskCandidates").cloned().unwrap_or_else(|| json!([])),
        "riskAuthority": contract
            .get("declared")
            .and_then(|d| d.get("riskAuthority"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// Port of `buildProductContext`.
pub fn build_product_context(projection: &Value, contract: &Value) -> Value {
    let base = extract_actors(projection, contract);
    let roles: Vec<Value> = base["roles"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|role| match role {
            Value::String(id) => json!({
                "id": id,
                "source": "observed-or-declared",
                "accountIds": [],
                "permissionIds": [],
            }),
            other => other,
        })
        .collect();

    let accounts: Vec<Value> = projection
        .get("accounts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|item| match item {
            Value::String(id) => json!({"id": id, "roleIds": [], "evidenceRefs": []}),
            other => other,
        })
        .collect();

    let permissions: Vec<Value> = projection
        .get("permissions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|item| match item {
            Value::String(id) => json!({"id": id, "roleIds": [], "scope": "unknown", "evidenceRefs": []}),
            other => other,
        })
        .collect();

    let role_ids: BTreeSet<String> = roles
        .iter()
        .filter_map(|r| r.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();

    let mut gaps: Vec<Value> = Vec::new();
    for account in &accounts {
        for role_id in account
            .get("roleIds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(role_id_str) = role_id.as_str() {
                if !role_ids.contains(role_id_str) {
                    gaps.push(json!({
                        "kind": "unknown-account-role",
                        "accountId": account.get("id").cloned().unwrap_or(Value::Null),
                        "roleId": role_id_str,
                    }));
                }
            }
        }
    }

    json!({
        "roles": base["roles"],
        "tenants": base["tenants"],
        "actors": roles,
        "accounts": accounts,
        "permissions": permissions,
        "bindings": projection.get("actorBindings").cloned().unwrap_or_else(|| json!([])),
        "gaps": gaps,
        "plans": str_set(projection, "plans", contract, "plans"),
        "entitlements": str_set(projection, "entitlements", contract, "entitlements"),
        "dataClasses": str_set(projection, "dataClasses", contract, "dataClasses"),
        "assets": projection.get("assets").cloned().unwrap_or_else(|| json!([])),
        "riskCandidates": projection.get("riskCandidates").cloned().unwrap_or_else(|| json!([])),
        "riskAuthority": contract.get("declared").and_then(|d| d.get("riskAuthority")).cloned().unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_actors_merges_and_sorts_observed_and_declared_roles() {
        let projection = json!({"roles": ["viewer"]});
        let contract = json!({"declared": {"roles": ["admin", "viewer"]}});
        let result = extract_actors(&projection, &contract);
        assert_eq!(result["roles"], json!(["admin", "viewer"]));
    }

    #[test]
    fn build_product_context_flags_unknown_account_role() {
        let projection = json!({
            "roles": ["admin"],
            "accounts": [{"id": "acct:1", "roleIds": ["ghost"]}],
        });
        let result = build_product_context(&projection, &json!({}));
        assert_eq!(result["gaps"].as_array().unwrap().len(), 1);
    }
}
