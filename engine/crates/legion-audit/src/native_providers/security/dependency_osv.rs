use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, files, same_binding, valid_digest};
use crate::dependency_inventory::{
    self, AdvisoryDatabase, AdvisoryRecord, Ecosystem, ManifestInput, SourceStatus,
};
use crate::{inventory::InventoryEnvelope, source_cache::bytes_digest};
use std::path::{Component, Path};

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
        env.insert(
            "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY".into(),
            Value::String(db.into()),
        );
    }
    json!({
        "executable": resolved_osv_scanner.into(),
        "args": ["scan", "source", "--offline", "--format", "json", "--all-packages", "--output", output_path.into(), "-r", repository_root.clone()],
        "cwd": repository_root,
        "timeoutMs": policy.and_then(|p| p.get("providerTimeoutMs")).and_then(Value::as_u64).unwrap_or(120_000),
        "maxOutputBytes": policy.and_then(|p| p.get("maxOutputBytes")).and_then(Value::as_u64).unwrap_or(8_388_608),
        "environmentKeys": ["PATH", "HOME", "USERPROFILE", "TEMP", "TMP", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"],
        "env": Value::Object(env),
    })
}

pub fn normalize_vulnerability(
    vuln: &Value,
    provider: Option<&str>,
    provider_version: Option<&str>,
) -> Value {
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
                vulnerabilities.push(normalize_vulnerability(
                    &vuln,
                    Some(provider),
                    Some(provider_version),
                ));
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
    // Frozen dependency inventory (A08): digests, freshness and unsupported or
    // unreadable lock inputs reach this provider's result. Absent inventory is
    // recorded, never invented; unsupported formats are blocking gaps.
    let inventory_summary = summarize_inventory(
        input
            .get("artifacts")
            .and_then(|a| a.get(INVENTORY_ARTIFACT)),
        &mut gaps,
    );
    // Findings are located at the manifest whose receipt carried them.
    let findings = receipts
        .iter()
        .flat_map(|r| {
            let manifest = r.get("manifest").cloned().unwrap_or(Value::Null);
            array(r.get("findings"))
                .into_iter()
                .map(move |mut finding| {
                    if let Some(object) = finding.as_object_mut() {
                        object.entry("manifest").or_insert_with(|| manifest.clone());
                    }
                    finding
                })
        })
        .collect::<Vec<_>>();
    json!({"status":if gaps.is_empty(){"pass"}else{"unproven"},"complete":gaps.is_empty(),"denominator":{"kind":"dependency-manifests","expected":manifests.len(),"examined":receipts.len()},"findings":findings,"coverageGaps":gaps,"dependencyInventory":inventory_summary})
}

/// Artifact key under `artifacts` carrying `frozen_inventory_artifact` output.
pub const INVENTORY_ARTIFACT: &str = "dependencyInventory";
const MAX_LOCK_BYTES: u64 = 8 * 1024 * 1024;

fn safe_relative(path: &str) -> bool {
    let p = Path::new(path);
    !path.is_empty()
        && !p.is_absolute()
        && p.components().all(|c| matches!(c, Component::Normal(_)))
}

/// Production wiring of `dependency_inventory::inventory`: read every frozen
/// lock/manifest input of `inventory` from `root` (bounded, symlink-free,
/// digest-verified against the frozen inventory), build the inventory, and
/// return the artifact `analyze` consumes. `scan` is the raw OSV scan that
/// supplied the advisory database (`None` leaves the advisory source absent,
/// which the inventory reports as its own gap).
pub fn frozen_inventory_artifact(
    root: &Path,
    inventory: &InventoryEnvelope,
    scan: Option<(&Value, &str, &str)>,
) -> Value {
    let mut manifests = Vec::new();
    let mut read_gaps = Vec::new();
    for entry in &inventory.entries {
        if !dependency_inventory::is_dependency_input(&entry.path) {
            continue;
        }
        let gap = |kind: &str| json!({"kind": kind, "path": entry.path});
        if !safe_relative(&entry.path) {
            read_gaps.push(gap("dependency-inventory-path-unsafe"));
            continue;
        }
        let full = root.join(&entry.path);
        let meta = match std::fs::symlink_metadata(&full) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => meta,
            _ => {
                read_gaps.push(gap("dependency-inventory-unreadable"));
                continue;
            }
        };
        if meta.len() > MAX_LOCK_BYTES {
            read_gaps.push(gap("dependency-inventory-oversize"));
            continue;
        }
        let Ok(bytes) = std::fs::read(&full) else {
            read_gaps.push(gap("dependency-inventory-unreadable"));
            continue;
        };
        let frozen = entry
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"));
        if frozen != Some(bytes_digest(&bytes).as_str()) {
            read_gaps.push(gap("dependency-lock-digest-mismatch"));
            continue;
        }
        let Ok(raw) = String::from_utf8(bytes) else {
            read_gaps.push(gap("dependency-inventory-not-utf8"));
            continue;
        };
        manifests.push(ManifestInput {
            path: entry.path.clone(),
            raw,
            target: String::new(),
        });
    }
    let database =
        scan.map(|(raw, version, digest)| advisory_database_from_scan(raw, version, digest));
    let built = dependency_inventory::inventory(&manifests, database.as_ref(), &[]);
    json!({
        "inventory": serde_json::to_value(&built).unwrap_or(Value::Null),
        "readGaps": read_gaps,
    })
}

/// Summary for `analysis.dependencyInventory`; pushes blocking gaps for
/// unsupported or unreadable inputs onto `gaps`.
fn summarize_inventory(artifact: Option<&Value>, gaps: &mut Vec<Value>) -> Value {
    let Some(artifact) = artifact else {
        return json!({"state": "absent", "claims": {"advisoryCurrent": false}});
    };
    let Some(inventory) = artifact.get("inventory").filter(|v| v.is_object()) else {
        gaps.push(json!({"kind": "dependency-inventory-invalid"}));
        return json!({"state": "invalid", "claims": {"advisoryCurrent": false}});
    };
    for gap in array(artifact.get("readGaps")) {
        gaps.push(gap);
    }
    for item in array(inventory.get("unsupported")) {
        gaps.push(json!({
            "kind": "dependency-lock-unsupported",
            "path": item.get("path").cloned().unwrap_or(Value::Null),
            "reason": item.get("reason").cloned().unwrap_or(Value::Null),
        }));
    }
    let freshness = inventory.get("freshness").cloned().unwrap_or(Value::Null);
    let advisory_current = freshness.get("advisory").and_then(Value::as_str) == Some("current");
    let mut gap_counts = serde_json::Map::new();
    for gap in array(inventory.get("gaps")) {
        if let Some(kind) = gap.get("kind").and_then(Value::as_str) {
            let slot = gap_counts.entry(kind.to_owned()).or_insert(json!(0));
            *slot = json!(slot.as_u64().unwrap_or(0) + 1);
        }
    }
    json!({
        "state": "present",
        "schemaVersion": inventory.get("schemaVersion").cloned().unwrap_or(Value::Null),
        "graphDigest": inventory.get("graphDigest").cloned().unwrap_or(Value::Null),
        "sourceDigest": inventory.get("sourceDigest").cloned().unwrap_or(Value::Null),
        "metadataDigest": inventory.get("metadataDigest").cloned().unwrap_or(Value::Null),
        "freshness": freshness,
        "manifestCount": array(inventory.get("manifests")).len(),
        "packageCount": array(inventory.get("packages")).len(),
        "unsupportedCount": array(inventory.get("unsupported")).len(),
        "inventoryComplete": inventory.get("complete").cloned().unwrap_or(json!(false)),
        "inventoryGapCounts": Value::Object(gap_counts),
        // Currency is never claimed unless the advisory source proved it.
        "claims": {"advisoryCurrent": advisory_current},
    })
}

// --- Advisory bridge into dependency_inventory (A08) ---
// Raw OSV output keeps affected/fixed pairs that normalize_vulnerability drops.
// Records are namespaced by OSV ecosystem mapped to the inventory registry.
// Unknown OSV ecosystems produce no record; inventory reports them as coverage gaps.

/// Builds the advisory database from one raw OSV scan. Freshness of an offline
/// database is not provable from the scan, so it stays `Unknown` unless the
/// caller supplies authenticated freshness; incomplete scans are `Partial`.
pub fn advisory_database_from_scan(
    raw: &Value,
    version: &str,
    database_digest: &str,
) -> AdvisoryDatabase {
    let incomplete = raw.get("scan_complete").and_then(Value::as_bool) == Some(false)
        || !array(raw.get("scan_incomplete_reasons")).is_empty();
    AdvisoryDatabase {
        version: version.to_owned(),
        digest: database_digest.to_owned(),
        status: if incomplete {
            SourceStatus::Partial
        } else {
            SourceStatus::Unknown
        },
        records: advisory_records_from_scan(raw),
    }
}

pub fn advisory_records_from_scan(raw: &Value) -> Vec<AdvisoryRecord> {
    let mut out = Vec::new();
    for result in array(raw.get("results")) {
        for source in array(result.get("packages")) {
            for vulnerability in array(source.get("vulnerabilities")) {
                out.extend(advisory_records(&vulnerability));
            }
        }
    }
    out
}

pub fn advisory_records(vulnerability: &Value) -> Vec<AdvisoryRecord> {
    let Some(id) = vulnerability
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for affected in array(vulnerability.get("affected")) {
        let Some(package) = affected.get("package") else {
            continue;
        };
        let osv_ecosystem_name = package
            .get("ecosystem")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some((ecosystem, registry)) = osv_ecosystem(osv_ecosystem_name) else {
            continue;
        };
        let Some(name) = package
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let mut fixed_versions = Vec::new();
        let mut range_events = false;
        for range in array(affected.get("ranges")) {
            for event in array(range.get("events")) {
                if let Some(fixed) = event.get("fixed").and_then(Value::as_str) {
                    fixed_versions.push(fixed.to_owned());
                } else if event.is_object() {
                    range_events = true;
                }
            }
        }
        out.push(AdvisoryRecord {
            id: id.to_owned(),
            ecosystem,
            registry: registry.to_owned(),
            name: name.to_owned(),
            affected_versions: strings(affected.get("versions")),
            fixed_versions,
            range_events,
        });
    }
    out
}

fn osv_ecosystem(name: &str) -> Option<(Ecosystem, &'static str)> {
    match name {
        "crates.io" => Some((Ecosystem::Cargo, "crates.io")),
        "npm" => Some((Ecosystem::Npm, "registry.npmjs.org")),
        "Go" => Some((Ecosystem::Golang, "proxy.golang.org")),
        "PyPI" => Some((Ecosystem::Pypi, "pypi.org")),
        _ => None,
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    let items = array(value);
    items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}
