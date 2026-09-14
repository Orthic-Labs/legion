use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, bool_value, files, same_binding, string, u64_value, valid_digest};

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

pub fn analyze(input: &Value) -> Value {
    let projection = input.get("projection");
    let source = files(projection)
        .into_iter()
        .filter(|path| {
            let lower = path.to_ascii_lowercase();
            lower.contains("dockerfile")
                || lower.ends_with(".yaml")
                || lower.ends_with(".yml")
                || lower.ends_with(".tf")
                || lower.contains("compose")
        })
        .collect::<Vec<_>>();
    let artifacts = input.get("artifacts");
    let rendered = artifacts
        .and_then(|a| a.get("renderedInfrastructure"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let evidence = artifacts.and_then(|a| a.get("iacEvidence"));
    let denominator = infrastructure_denominator(&source, &rendered);
    let mut gaps = denominator
        .get("gaps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let plan_binding = input.get("plan").and_then(|p| p.get("binding"));
    let valid = evidence.is_some_and(|e| {
        same_binding(e.get("binding"), plan_binding)
            && e.get("executionReceipt")
                .and_then(|r| r.get("complete"))
                .and_then(Value::as_bool)
                == Some(true)
            && valid_digest(
                e.get("executionReceipt")
                    .and_then(|r| r.get("tool"))
                    .and_then(|t| t.get("executableDigest")),
            )
            && valid_digest(e.get("databaseDigest"))
            && u64_value(e.get("examined"), 0) == (source.len() + rendered.len()) as u64
    });
    if !valid {
        gaps.push(json!({"kind": "iac-evidence-invalid"}));
    }
    let findings = array(evidence.and_then(|e| e.get("findings")));
    json!({"status": if !gaps.is_empty() { "unproven" } else if !findings.is_empty() { "fail" } else { "pass" }, "complete": gaps.is_empty(), "denominator": {"kind": "infrastructure-resources", "expected": source.len() + rendered.len(), "examined": evidence.and_then(|e| e.get("examined")).and_then(Value::as_u64).unwrap_or(0)}, "findings": findings, "coverageGaps": gaps})
}
