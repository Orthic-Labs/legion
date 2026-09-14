use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, files, same_binding, u64_value, valid_digest};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyReceipt {
    pub schema_version: u32,
    pub package: Value,
    pub advisory: Value,
    pub path: Vec<Value>,
    pub database: Value,
    pub reachability: String,
    pub fixed_versions: Vec<Value>,
    pub complete: bool,
    pub coverage_gaps: Vec<Value>,
}

pub fn normalize_dependency_receipt(
    package: &Value,
    advisory: &Value,
    database: &Value,
    path: &[Value],
) -> Result<DependencyReceipt, String> {
    if package
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || package
            .get("version")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || advisory
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("dependency receipt requires package version and advisory".into());
    }
    let mut gaps = Vec::new();
    if database
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        == "unknown"
    {
        gaps.push(json!({"kind":"advisory-database-unknown"}));
    }
    if database
        .get("version")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || !valid_digest(database.get("digest"))
    {
        gaps.push(json!({"kind":"advisory-database-identity-unproven"}));
    }
    if path.is_empty() {
        gaps.push(json!({"kind":"dependency-path-unproven"}));
    }
    Ok(DependencyReceipt {
        schema_version: 1,
        package: package.clone(),
        advisory: advisory.clone(),
        path: path.to_vec(),
        database: database.clone(),
        reachability: "unknown".into(),
        fixed_versions: array(advisory.get("fixedVersions")),
        complete: gaps.is_empty(),
        coverage_gaps: gaps,
    })
}

pub fn inventory_manifests(projection: &Value) -> Vec<Value> {
    let mut paths = files(Some(projection))
        .into_iter()
        .filter(|path| {
            let lower = path.to_ascii_lowercase();
            lower.contains("package-lock")
                || lower.contains("pnpm-lock")
                || lower.contains("yarn.lock")
                || lower.contains("cargo.lock")
                || lower.contains("go.sum")
                || lower.contains("requirements")
                || lower.contains("poetry.lock")
                || lower.ends_with(".csproj")
                || lower.ends_with("pom.xml")
                || lower.contains("gradle")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| json!({"path":path,"status":"observed","parsed":false,"coverage":"unproven"}))
        .collect()
}

pub fn analyze(input: &Value) -> Value {
    let manifests = inventory_manifests(input.get("projection").unwrap_or(&Value::Null));
    let receipts = array(
        input
            .get("artifacts")
            .and_then(|a| a.get("dependencyReceipts")),
    );
    let mut gaps = Vec::new();
    if manifests.is_empty() {
        gaps.push(json!({"kind":"dependency-manifest-denominator-zero"}));
    }
    for manifest in &manifests {
        let path = manifest
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let receipt = receipts
            .iter()
            .find(|item| item.get("manifest").and_then(Value::as_str) == Some(path));
        let Some(receipt) = receipt else {
            gaps.push(json!({"kind":"dependency-manifest-unparsed","path":path}));
            continue;
        };
        let valid = same_binding(
            receipt.get("binding"),
            input.get("plan").and_then(|p| p.get("binding")),
        ) && receipt
            .get("executionReceipt")
            .and_then(|r| r.get("complete"))
            .and_then(Value::as_bool)
            == Some(true)
            && valid_digest(
                receipt
                    .get("executionReceipt")
                    .and_then(|r| r.get("tool"))
                    .and_then(|t| t.get("executableDigest")),
            )
            && valid_digest(receipt.get("database").and_then(|d| d.get("digest")))
            && receipt
                .get("database")
                .and_then(|d| d.get("version"))
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
            && !array(receipt.get("paths")).is_empty()
            && array(receipt.get("paths")).iter().all(|p| {
                matches!(
                    p.get("reachability").and_then(Value::as_str),
                    Some("reachable" | "unreachable")
                )
            });
        if !valid {
            gaps.push(json!({"kind":"dependency-receipt-invalid","path":path}));
        }
    }
    let findings = receipts
        .iter()
        .flat_map(|r| array(r.get("findings")))
        .collect::<Vec<_>>();
    json!({"status":if gaps.is_empty(){"pass"}else{"unproven"},"complete":gaps.is_empty(),"denominator":{"kind":"dependency-manifests","expected":manifests.len(),"examined":receipts.len()},"findings":findings,"coverageGaps":gaps})
}
