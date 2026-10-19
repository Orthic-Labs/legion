use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, digest, digest_json, files, same_binding, valid_digest};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandContract {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub environment_keys: Vec<String>,
}

pub fn trivy_command(
    resolved_trivy: impl Into<String>,
    repository_root: impl Into<String>,
    policy: Option<&Value>,
    output_path: impl Into<String>,
    scoped: Option<&str>,
) -> CommandContract {
    let root = repository_root.into();
    let output = output_path.into();
    let scope = scoped.unwrap_or("fs");
    CommandContract {
        executable: resolved_trivy.into(),
        args: vec![
            scope.into(),
            "--format".into(),
            "json".into(),
            "--output".into(),
            output,
            root.clone(),
        ],
        cwd: root,
        timeout_ms: policy
            .and_then(|p| p.get("providerTimeoutMs"))
            .and_then(Value::as_u64)
            .unwrap_or(120_000),
        max_output_bytes: policy
            .and_then(|p| p.get("maxOutputBytes"))
            .and_then(Value::as_u64)
            .unwrap_or(8_388_608),
        environment_keys: vec![
            "PATH".into(),
            "HOME".into(),
            "USERPROFILE".into(),
            "TEMP".into(),
            "TMP".into(),
            "TRIVY_OFFLINE_DB".into(),
        ],
    }
}

pub fn normalize_iac_finding(
    finding: &Value,
    provider: Option<&str>,
    provider_version: Option<&str>,
) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-iac-finding",
        "provider": provider.unwrap_or("container-iac.trivy"),
        "providerVersion": provider_version.unwrap_or("0.50.0"),
        "ruleId": finding.get("rule_id").or_else(|| finding.get("ID")).or_else(|| finding.get("id")).cloned().unwrap_or(Value::Null),
        "severity": finding.get("severity").or_else(|| finding.get("Severity")).cloned().unwrap_or(Value::Null),
        "target": finding.get("target").or_else(|| finding.get("Target")).cloned().unwrap_or(Value::Null),
        "resource": finding.get("resource").or_else(|| finding.get("Misconfiguration").and_then(|v| v.get("resource"))).cloned().unwrap_or(Value::Null),
        "message": finding.get("message").or_else(|| finding.get("Description")).cloned().unwrap_or(Value::Null),
        "toolDb": finding.get("db").cloned().unwrap_or(Value::Null),
        "evidenceRefs": [],
    })
}

pub fn offline_state(
    offline: bool,
    database_digest: Option<&str>,
    database_version: Option<&str>,
) -> Value {
    json!({"schemaVersion": 1, "kind": "legion-iac-offline-state", "offline": offline, "databaseDigest": database_digest, "databaseVersion": database_version})
}

pub fn infrastructure_denominator(source: &[String], rendered: &[Value]) -> Value {
    json!({"schemaVersion": 1, "source": source, "rendered": rendered, "gaps": if rendered.is_empty() { vec!["rendered-resources-absent"] } else { Vec::<&str>::new() }, "complete": !source.is_empty() && !rendered.is_empty()})
}

/// Existing supported source predicate; selection remains the frozen provider scope.
pub(super) fn is_iac_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("dockerfile")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".tf")
        || lower.contains("compose")
}

pub(super) fn config_target(root: &Path, raw: &str) -> Option<String> {
    let path = Path::new(raw);
    let relative = if path.is_absolute() {
        path.strip_prefix(root).ok()?
    } else {
        path
    };
    let text = relative.to_str()?;
    if text.is_empty()
        || text.contains('\\')
        || text.contains(':')
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    let normalized = relative
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    (!normalized.is_empty()).then_some(normalized)
}

pub fn analyze(input: &Value) -> Value {
    let selected = files(input.get("projection"));
    let selected_set: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
    let source: BTreeSet<&str> = selected_set
        .iter()
        .copied()
        .filter(|path| is_iac_path(path))
        .collect();
    let artifacts = input.get("artifacts");
    let evidence = artifacts.and_then(|a| a.get("iacEvidence"));
    let scope = input.pointer("/plan/selectedDenominator");
    let binding = input.pointer("/plan/binding");
    let mut gaps = Vec::<Value>::new();
    let frozen_entries = array(scope.and_then(|s| s.get("entries")));
    let frozen_by_path: BTreeMap<&str, &Value> = frozen_entries
        .iter()
        .filter_map(|entry| Some((entry.get("path")?.as_str()?, entry)))
        .collect();
    let scope_valid = selected_set.len() == selected.len()
        && frozen_entries.len() == selected.len()
        && frozen_by_path.len() == selected.len()
        && frozen_by_path
            .keys()
            .all(|path| selected_set.contains(path))
        && scope.is_some_and(|s| {
            valid_digest(s.get("digest"))
                && s.get("digest") == s.get("computedDigest")
                && s.get("count").and_then(Value::as_u64) == Some(selected.len() as u64)
                && s.get("count") == s.get("computedCount")
        });
    if !scope_valid {
        gaps.push(json!({"kind": "iac-frozen-selection-invalid"}));
    }
    let receipt = evidence.and_then(|e| e.get("executionReceipt"));
    let binding_valid = binding.is_some_and(|b| {
        valid_digest(b.get("digest"))
            && b.get("repositoryRevision")
                .and_then(Value::as_str)
                .is_some_and(|revision| !revision.is_empty())
    }) && evidence.is_some_and(|e| same_binding(e.get("binding"), binding))
        && receipt.is_some_and(|r| {
            same_binding(r.get("binding"), binding) && r.get("selectedDenominator") == scope
        });
    if !binding_valid {
        gaps.push(json!({"kind": "iac-receipt-binding-invalid"}));
    }
    let receipt_valid = receipt.is_some_and(|r| {
        r.get("complete").and_then(Value::as_bool) == Some(true)
            && r.get("state").and_then(Value::as_str) == Some("completed")
            && r.get("exitCode").and_then(Value::as_i64) == Some(0)
            && r.pointer("/tool/name").and_then(Value::as_str) == Some("trivy")
            && valid_digest(r.pointer("/tool/executableDigest"))
            && r.get("executableDigest") == r.pointer("/tool/executableDigest")
            && valid_digest(r.get("stdoutDigest"))
            && r.get("stdoutBytes")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)
            && r.get("receiptId")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
            && r.get("policyId")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
            && r.pointer("/sandbox/required").and_then(Value::as_bool) == Some(true)
            && r.pointer("/sandbox/networkEnabled")
                .and_then(Value::as_bool)
                == Some(true)
            && r.pointer("/sandbox/receiptId")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with("sandbox:"))
    });
    if !receipt_valid {
        gaps.push(json!({"kind": "iac-execution-receipt-invalid"}));
    }
    // This identifies the version of embedded checks, not database content bytes.
    let database_valid = evidence.is_some_and(|e| {
        let version = receipt
            .and_then(|r| r.pointer("/tool/version"))
            .and_then(Value::as_str);
        e.get("databaseIdentityKind").and_then(Value::as_str)
            == Some("embedded-checks-version-derived")
            && version.is_some_and(|v| {
                !v.trim().is_empty()
                    && e.get("databaseDigest").and_then(Value::as_str)
                        == Some(digest(format!("trivy-builtin-checks\0{v}").as_bytes()).as_str())
            })
            && valid_digest(e.get("databaseDigest"))
    });
    if !database_valid {
        gaps.push(json!({"kind": "iac-database-identity-invalid"}));
    }
    let trusted_run = scope_valid && binding_valid && receipt_valid && database_valid;

    let dispositions = array(evidence.and_then(|e| e.get("sourceDispositions")));
    let mut by_path = BTreeMap::<&str, Vec<&Value>>::new();
    for row in &dispositions {
        match row.get("path").and_then(Value::as_str) {
            Some(path) if selected_set.contains(path) => by_path.entry(path).or_default().push(row),
            _ => gaps.push(json!({"kind": "iac-source-disposition-outside-selection"})),
        }
    }
    let mut outside = BTreeSet::new();
    let mut valid_sources = BTreeSet::new();
    for path in &selected_set {
        let Some(rows) = by_path.get(path).filter(|rows| rows.len() == 1) else {
            gaps.push(json!({"kind": "iac-source-disposition-missing-or-duplicate", "path": path}));
            continue;
        };
        let row = rows[0];
        let applicable = source.contains(path);
        let disposition = if applicable {
            "applicable-iac"
        } else {
            "outside-supported-iac-scope"
        };
        if row.get("disposition").and_then(Value::as_str) != Some(disposition) {
            gaps.push(json!({"kind": "iac-source-disposition-invalid", "path": path}));
            continue;
        }
        // An outside-scope classification excludes scanner work, never frozen
        // byte validation required to count a selected path as examined.
        if row.get("state").and_then(Value::as_str) == Some("validated")
            && valid_digest(row.get("frozenDigest"))
            && frozen_by_path
                .get(path)
                .and_then(|entry| entry.get("digest"))
                == row.get("frozenDigest")
            && row.get("frozenDigest") == row.get("observedDigest")
            && row.get("frozenDigest") == row.get("postScanDigest")
        {
            if applicable {
                valid_sources.insert(*path);
            } else {
                outside.insert(*path);
            }
        } else {
            let kind = row
                .get("reason")
                .and_then(Value::as_str)
                .filter(|kind| {
                    matches!(
                        *kind,
                        "iac-source-unreadable"
                            | "iac-source-digest-missing"
                            | "iac-source-drift"
                            | "iac-source-path-invalid"
                    )
                })
                .unwrap_or("iac-source-identity-invalid");
            gaps.push(json!({"kind": kind, "path": path}));
        }
    }
    let raw_results = evidence
        .and_then(|e| e.get("rawResults"))
        .and_then(Value::as_array);
    if raw_results.is_none() {
        gaps.push(json!({"kind": "iac-config-output-invalid"}));
    }
    // Distinct genuine config result records are observations of configuration,
    // never proof that a deployment was rendered or executed.
    let mut records = BTreeMap::<String, &Value>::new();
    for raw in raw_results.into_iter().flatten() {
        if raw.get("Class").and_then(Value::as_str) == Some("config") {
            records.entry(digest_json(raw)).or_insert(raw);
        } else {
            gaps.push(json!({"kind": "iac-config-output-invalid"}));
        }
    }
    if records.is_empty() {
        gaps.push(json!({"kind": "rendered-resources-absent"}));
    }
    let observations = array(artifacts.and_then(|a| a.get("renderedInfrastructure")));
    let mut observed = BTreeMap::<&str, Vec<&Value>>::new();
    for row in &observations {
        if let Some(id) = row.get("rawResultDigest").and_then(Value::as_str) {
            observed.entry(id).or_default().push(row);
        } else {
            gaps.push(json!({"kind": "iac-config-observation-invalid"}));
        }
    }
    if observed.keys().any(|id| !records.contains_key(*id)) {
        gaps.push(json!({"kind": "iac-config-observation-without-result"}));
    }
    let mut covered = BTreeSet::<&str>::new();
    let mut examined_records = 0usize;
    let root = input
        .pointer("/plan/repositoryBinding/root")
        .and_then(Value::as_str)
        .map(Path::new);
    for (id, raw) in &records {
        let Some(rows) = observed.get(id.as_str()).filter(|rows| rows.len() == 1) else {
            gaps.push(json!({"kind": "iac-config-observation-missing-or-duplicate", "rawResultDigest": id}));
            continue;
        };
        let row = rows[0];
        let target = row.get("target").and_then(Value::as_str);
        let record_valid = target.is_some_and(|path| source.contains(path))
            && raw
                .get("Type")
                .and_then(Value::as_str)
                .is_some_and(|kind| !kind.is_empty())
            && row.get("type") == raw.get("Type")
            && raw
                .get("Target")
                .and_then(Value::as_str)
                .is_some_and(|target| {
                    row.get("reportedTarget").and_then(Value::as_str) == Some(target)
                })
            && root
                .and_then(|root| {
                    raw.get("Target")
                        .and_then(Value::as_str)
                        .and_then(|target| config_target(root, target))
                })
                .as_deref()
                == target
            && raw.get("Misconfigurations").is_none_or(Value::is_array)
            && raw
                .get("MisconfigurationSummary")
                .is_none_or(Value::is_object);
        if !record_valid {
            gaps.push(
                json!({"kind": "iac-config-result-correspondence-invalid", "rawResultDigest": id}),
            );
            continue;
        }
        if trusted_run && target.is_some_and(|path| valid_sources.contains(path)) {
            covered.insert(target.unwrap());
            examined_records += 1;
        }
    }
    for path in &source {
        if !covered.contains(path) {
            gaps.push(json!({"kind": "iac-source-result-missing", "path": path}));
        }
    }
    let expected = source.len() + records.len();
    let examined = covered.len() + examined_records;
    let evidence_count_valid = evidence
        .and_then(|e| e.get("examined"))
        .and_then(Value::as_u64)
        == Some(examined as u64);
    if !evidence_count_valid {
        gaps.push(json!({"kind": "iac-evidence-count-invalid"}));
    }
    if !trusted_run || !evidence_count_valid {
        gaps.push(json!({"kind": "iac-evidence-invalid"}));
    }
    let mut validated_paths = outside;
    validated_paths.extend(covered);
    let findings = array(evidence.and_then(|e| e.get("findings")));
    let complete = gaps.is_empty() && expected > 0 && expected == examined;
    json!({"status": if !complete { "unproven" } else if !findings.is_empty() { "fail" } else { "pass" },
        "complete": complete,
        "denominator": {"kind": "infrastructure-resources", "expected": expected, "examined": examined},
        "sourceCoverage": {"selectedCount": selected.len(), "validatedPaths": validated_paths,
            "complete": complete && validated_paths.len() == selected.len(),
            "frozenDenominatorDigest": scope.and_then(|s| s.get("digest")),
            "frozenDenominatorCount": scope.and_then(|s| s.get("count"))},
        "configObservationCount": records.len(), "findings": findings, "coverageGaps": gaps})
}
