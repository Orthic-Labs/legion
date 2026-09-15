use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, digest_json, exact_binding, string, valid_digest};

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

pub fn candidate_id(
    provider: &str,
    rule_id: &str,
    file: Option<&str>,
    line: u64,
    trace_digest: Option<&str>,
) -> String {
    let body = json!({"provider":provider,"ruleId":rule_id,"file":file,"line":line,"traceDigest":trace_digest});
    super::common::digest(
        format!(
            "opengrep-candidate\0{}",
            serde_json::to_string(&body).unwrap_or_default()
        )
        .as_bytes(),
    )
}

pub fn ruleset_identity(
    path: Option<&str>,
    digest: Option<&str>,
    license: Option<&str>,
    source: Option<&str>,
    version: Option<&str>,
) -> Value {
    json!({"schemaVersion":1,"kind":"legion-opengrep-ruleset","path":path,"digest":digest,"license":license,"source":source,"version":version})
}

pub fn normalize_finding(
    finding: &Value,
    provider: Option<&str>,
    provider_version: Option<&str>,
    ruleset: Option<&Value>,
) -> Value {
    let path = string(finding.get("path").or_else(|| finding.get("file")));
    let line = finding
        .get("start")
        .and_then(|s| s.get("line"))
        .and_then(Value::as_u64)
        .or_else(|| finding.get("line").and_then(Value::as_u64))
        .unwrap_or(1);
    let trace = finding
        .get("dataflow_trace")
        .or_else(|| finding.get("taint_sink"));
    let capability = if trace.is_none() {
        "pattern"
    } else if trace
        .and_then(|v| v.get("interfile_vars"))
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty())
        || trace.and_then(|v| v.get("interproc")).is_some()
    {
        "interfile"
    } else {
        "intrafile"
    };
    let source = trace.and_then(|t| t.get("source")).and_then(Value::as_array).and_then(|v| v.first()).and_then(Value::as_array).map(|v| json!({"file":v.first().and_then(Value::as_str),"line":v.get(1).and_then(Value::as_u64).unwrap_or(0)}));
    let sink = trace.and_then(|t| t.get("sink")).and_then(Value::as_array).and_then(|v| v.first()).and_then(Value::as_array).map(|v| json!({"file":v.first().and_then(Value::as_str),"line":v.get(1).and_then(Value::as_u64).unwrap_or(0)}));
    let intermediate = trace.and_then(|t| t.get("intermediate_vars")).and_then(Value::as_array).map(|vars| vars.iter().filter_map(|v| v.as_array()).map(|v| json!({"file":v.first().and_then(Value::as_str),"line":v.get(1).and_then(Value::as_u64).unwrap_or(0)})).collect::<Vec<_>>()).unwrap_or_default();
    let end_line = finding
        .get("end")
        .and_then(|e| e.get("line"))
        .and_then(Value::as_u64)
        .unwrap_or(line);
    let column = finding
        .get("start")
        .and_then(|s| s.get("col"))
        .and_then(Value::as_u64)
        .or_else(|| finding.get("column").and_then(Value::as_u64))
        .unwrap_or(0);
    let end_col = finding
        .get("end")
        .and_then(|e| e.get("col"))
        .and_then(Value::as_u64)
        .or_else(|| finding.get("column").and_then(Value::as_u64))
        .unwrap_or(0);
    json!({"schemaVersion":1,"kind":"legion-opengrep-finding","provider":provider.unwrap_or("opengrep.sast"),"providerVersion":provider_version.unwrap_or("1.0.0"),"ruleset":ruleset,"ruleId":finding.get("check_id").or_else(|| finding.get("ruleId")).cloned().unwrap_or_else(|| Value::String("opengrep.rule".into())),"severity":finding.get("extra").and_then(|e| e.get("severity")).or_else(|| finding.get("severity")).cloned().unwrap_or_else(|| Value::String("warning".into())),"message":finding.get("extra").and_then(|e| e.get("message")).or_else(|| finding.get("message")).or_else(|| finding.get("check_id")).cloned().unwrap_or(Value::Null),"file":path,"range":{"start":{"line":line,"column":column},"end":{"line":end_line,"column":end_col}},"capability":capability,"source":source,"sink":sink,"intermediateVars":intermediate,"evidenceRefs":[]})
}

pub fn to_candidate(
    finding: &Value,
    provider: Option<&str>,
    provider_version: Option<&str>,
    denominator_digest: Option<&str>,
) -> Value {
    let provider = provider.unwrap_or("opengrep.sast");
    let rule = finding
        .get("ruleId")
        .and_then(Value::as_str)
        .unwrap_or("opengrep.rule");
    let file = finding.get("file").and_then(Value::as_str);
    let line = finding
        .get("range")
        .and_then(|r| r.get("start"))
        .and_then(|s| s.get("line"))
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let trace_digest = (finding.get("source").is_some_and(|v| !v.is_null())
        || finding.get("sink").is_some_and(|v| !v.is_null()))
    .then(|| {
        digest_json(&json!([
            finding.get("source"),
            finding.get("sink"),
            finding.get("intermediateVars")
        ]))
    });
    let severity = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("warning");
    let hint = if severity.eq_ignore_ascii_case("error") {
        "high"
    } else {
        "medium"
    };
    json!({"schemaVersion":2,"kind":"security-candidate","id":candidate_id(provider,rule,file,line,trace_digest.as_deref()),"provider":provider,"providerVersion":provider_version.unwrap_or("1.0.0"),"ruleId":rule,"candidateClass":"sast","claim":finding.get("message"),"severityHint":hint,"sources":finding.get("source").and_then(|v|v.get("file")).and_then(Value::as_str).map(|v|vec![v]).unwrap_or_default(),"sinks":finding.get("sink").and_then(|v|v.get("file")).and_then(Value::as_str).map(|v|vec![v]).unwrap_or_default(),"attackerCapabilities":[],"preconditions":[],"effects":[],"assets":[],"trustBoundaryCrossings":[],"requiredControls":[],"observedControls":[],"chainRoles":[],"evidenceRefs":finding.get("evidenceRefs").cloned().unwrap_or_else(||json!([])),"detectorMetadata":{"capability":finding.get("capability"),"source":finding.get("source"),"sink":finding.get("sink"),"intermediateVars":finding.get("intermediateVars")},"uncertainty":["A pattern match is never a vulnerability by itself; adjudication is required."],"binding":null,"denominatorDigest":denominator_digest,"verdict":"UNADJUDICATED","adjudicationRequired":true})
}

pub fn command_contract(
    resolved: impl Into<String>,
    json_path: impl Into<String>,
    sarif_path: impl Into<String>,
    rules_path: impl Into<String>,
    frozen_paths: &[String],
    root: impl Into<String>,
    policy: Option<&Value>,
) -> CommandContract {
    let root = root.into();
    let mut args = vec![
        "scan".into(),
        "--json-output".into(),
        json_path.into(),
        "--sarif-output".into(),
        sarif_path.into(),
        "--metrics".into(),
        "off".into(),
        "--disable-version-check".into(),
        "-f".into(),
        rules_path.into(),
    ];
    args.extend(frozen_paths.iter().cloned());
    CommandContract {
        executable: resolved.into(),
        args,
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
        ],
    }
}

pub fn provider_result(evidence: &Value) -> Result<Value, String> {
    let binding = evidence.get("binding");
    if !exact_binding(binding, evidence.get("expectedBinding").or(binding))
        || !valid_digest(binding.and_then(|b| b.get("digest")))
        || !valid_digest(evidence.get("denominator").and_then(|d| d.get("digest")))
        || evidence
            .get("denominator")
            .and_then(|d| d.get("expected"))
            .and_then(Value::as_u64)
            .is_none()
        || evidence
            .get("denominator")
            .and_then(|d| d.get("examined"))
            .and_then(Value::as_u64)
            != evidence
                .get("denominator")
                .and_then(|d| d.get("expected"))
                .and_then(Value::as_u64)
        || !valid_digest(evidence.get("ruleset").and_then(|r| r.get("digest")))
        || evidence
            .get("tool")
            .and_then(|t| t.get("name"))
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || evidence
            .get("tool")
            .and_then(|t| t.get("version"))
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !valid_digest(evidence.get("tool").and_then(|t| t.get("executableDigest")))
        || evidence
            .get("executionReceipt")
            .and_then(|r| r.get("complete"))
            .and_then(Value::as_bool)
            != Some(true)
        || evidence
            .get("executionReceipt")
            .and_then(|r| r.get("tool"))
            .and_then(|t| t.get("executableDigest"))
            != evidence.get("tool").and_then(|t| t.get("executableDigest"))
        || !valid_digest(
            evidence
                .get("executionReceipt")
                .and_then(|r| r.get("stdoutArtifact"))
                .and_then(|a| a.get("digest")),
        )
    {
        return Err("OpenGrep result requires matching binding denominator rules execution receipt and sealed tool digest".into());
    }
    Ok(
        json!({"schemaVersion":1,"provider":"security.opengrep","status":"candidates","complete":true,"binding":binding,"denominator":evidence.get("denominator"),"ruleset":evidence.get("ruleset"),"tool":evidence.get("tool"),"executionReceipt":evidence.get("executionReceipt"),"candidates":array(evidence.get("candidates")),"findings":[],"coverageGaps":[]}),
    )
}

pub fn analyze(input: &Value) -> Value {
    let evidence = input.get("artifacts").and_then(|a| a.get("opengrep"));
    let Some(evidence) = evidence else {
        return json!({"status":"unproven","complete":false,"denominator":{"kind":"sealed-source-paths","expected":input.get("plan").and_then(|p|p.get("denominator")).and_then(|d|d.get("pathCount")).and_then(Value::as_u64).unwrap_or(0),"examined":0},"findings":[],"candidates":[],"coverageGaps":[{"kind":"opengrep-evidence-missing"}]});
    };
    match provider_result(evidence) {
        Ok(result) => result,
        Err(reason) => {
            json!({"status":"unproven","complete":false,"denominator":{"kind":"sealed-source-paths","expected":0,"examined":0},"findings":[],"candidates":[],"coverageGaps":[{"kind":"opengrep-evidence-invalid","reason":reason}]})
        }
    }
}
