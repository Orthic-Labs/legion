use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, files, same_binding, valid_digest};

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

// --- OSV-Scanner v2 (src/providers/osv/index.mjs port) ---
// Distinguishes direct/transitive/reachable-unknown and preserves
// package/lockfile evidence. The vulnerability database is never updated
// during an offline audit.

pub fn osv_command(
    resolved_osv_scanner: impl Into<String>,
    output_path: impl Into<String>,
    repository_root: impl Into<String>,
    policy: Option<&Value>,
    offline_db: Option<&str>,
) -> Value {
    let repository_root = repository_root.into();
    let mut env = serde_json::Map::new();
    if let Some(db) = offline_db {
        env.insert("OSV_SCANNER_OFFLINE_DB".into(), Value::String(db.into()));
    }
    json!({
        "executable": resolved_osv_scanner.into(),
        "args": ["scan", "--format", "json", "--output", output_path.into(), repository_root.clone()],
        "cwd": repository_root,
        "timeoutMs": policy.and_then(|p| p.get("providerTimeoutMs")).and_then(Value::as_u64).unwrap_or(120_000),
        "maxOutputBytes": policy.and_then(|p| p.get("maxOutputBytes")).and_then(Value::as_u64).unwrap_or(8_388_608),
        "environmentKeys": ["PATH", "HOME", "USERPROFILE", "TEMP", "TMP", "OSV_SCANNER_OFFLINE_DB"],
        "env": Value::Object(env),
    })
}

pub fn normalize_vulnerability(vuln: &Value, provider: Option<&str>, provider_version: Option<&str>) -> Value {
    let source = vuln
        .get("related")
        .or_else(|| vuln.get("aliases"))
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![]));
    let source_slice: Vec<Value> = source
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .take(10)
        .collect();
    let package = vuln.get("package");
    json!({
        "schemaVersion": 1,
        "kind": "legion-osv-vulnerability",
        "provider": provider.unwrap_or("osv.scanner"),
        "providerVersion": provider_version.unwrap_or("2.0.0"),
        "id": vuln.get("id").or_else(|| vuln.get("ghsa_id")).cloned().unwrap_or(Value::Null),
        "package": {
            "name": package.and_then(|p| p.get("name")).cloned().unwrap_or(Value::Null),
            "ecosystem": package.and_then(|p| p.get("ecosystem")).cloned().unwrap_or(Value::Null),
            "version": package.and_then(|p| p.get("version")).or_else(|| package.and_then(|p| p.get("purl"))).cloned().unwrap_or(Value::Null),
            "purl": package.and_then(|p| p.get("purl")).cloned().unwrap_or(Value::Null),
        },
        "summary": vuln.get("summary").cloned().unwrap_or(Value::Null),
        "severity": vuln.get("severity").cloned().unwrap_or_else(|| vuln.get("database_specific").and_then(|d| d.get("severity")).cloned().unwrap_or(Value::Null)),
        "references": source_slice,
        "reachability": "unknown",
        "evidenceRefs": [],
    })
}

pub fn normalize_scan_result(
    raw: &Value,
    provider: Option<&str>,
    provider_version: Option<&str>,
    offline_db: Option<&str>,
    db_digest: Option<&str>,
) -> Value {
    let provider = provider.unwrap_or("osv.scanner");
    let provider_version = provider_version.unwrap_or("2.0.0");
    let mut vulnerabilities = Vec::new();
    let mut examined = Vec::new();
    for result in array(raw.get("results")) {
        for source in array(result.get("packages")) {
            let package_id = source
                .get("package")
                .and_then(|p| p.get("purl"))
                .or_else(|| source.get("package").and_then(|p| p.get("name")))
                .cloned()
                .unwrap_or(Value::Null);
            examined.push(package_id);
            for vuln in array(source.get("vulnerabilities")) {
                vulnerabilities.push(normalize_vulnerability(&vuln, Some(provider), Some(provider_version)));
            }
        }
    }
    let coverage_gaps: Vec<Value> = array(raw.get("scan_incomplete_reasons"))
        .into_iter()
        .map(|reason| json!({"kind": "osv-incomplete", "reason": reason}))
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-osv-result",
        "provider": provider,
        "providerVersion": provider_version,
        "offline": offline_db.is_some(),
        "databaseDigest": db_digest.map(Value::from).unwrap_or(Value::Null),
        "packageCount": examined.len(),
        "vulnerabilities": vulnerabilities,
        "examined": examined,
        "complete": raw.get("scan_complete").and_then(Value::as_bool).unwrap_or(true),
        "coverageGaps": coverage_gaps,
    })
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
