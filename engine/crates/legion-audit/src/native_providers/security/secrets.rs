use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, valid_digest};

const REDACTED: &str = "[REDACTED]";

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

pub fn redact(value: Option<&Value>) -> Value {
    if value.is_some_and(|v| !v.is_null()) {
        Value::String(REDACTED.into())
    } else {
        Value::Null
    }
}

pub fn gitleaks_command(
    resolved: impl Into<String>,
    root: impl Into<String>,
    mode: &str,
    policy: Option<&Value>,
    report: impl Into<String>,
) -> CommandContract {
    let root = root.into();
    let report = report.into();
    let args = if mode == "history" {
        vec![
            "git".into(),
            root.clone(),
            "--log-opts=--full-history --all".into(),
            "--report-format".into(),
            "json".into(),
            "--report-path".into(),
            report,
            "--no-banner".into(),
        ]
    } else {
        vec![
            "detect".into(),
            "--source".into(),
            root.clone(),
            "--report-format".into(),
            "json".into(),
            "--report-path".into(),
            report,
            "--no-banner".into(),
        ]
    };
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

pub fn normalize_finding(
    finding: &Value,
    provider: Option<&str>,
    provider_version: Option<&str>,
    mode: &str,
) -> Value {
    let rule = finding.get("RuleID").or_else(|| finding.get("ruleId"));
    let file = finding.get("File").or_else(|| finding.get("file"));
    let line = finding
        .get("StartLine")
        .or_else(|| finding.get("line"))
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let end_line = finding
        .get("EndLine")
        .or_else(|| finding.get("endLine"))
        .cloned()
        .unwrap_or(Value::Null);
    let digest_value = finding
        .get("SecretDigest")
        .or_else(|| finding.get("secretDigest"));
    let secret_digest = valid_digest(digest_value)
        .then(|| digest_value.cloned().unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    json!({"schemaVersion":1,"kind":"legion-secret-finding","provider":provider.unwrap_or("secrets.gitleaks"),"providerVersion":provider_version.unwrap_or("8.18.0"),"ruleId":rule.cloned().unwrap_or_else(|| Value::String("secret.unknown".into())),"file":file.cloned().unwrap_or(Value::Null),"line":line,"endLine":end_line,"secretType":rule.cloned().unwrap_or(Value::Null),"secretDigest":secret_digest,"match":if finding.get("Match").is_some_and(|v| !v.is_null()) {Value::String(REDACTED.into())} else {Value::Null},"commit":finding.get("Commit").or_else(|| finding.get("commit")).cloned().unwrap_or(Value::Null),"mode":mode,"validity":finding.get("Validity").or_else(|| finding.get("validity")).and_then(Value::as_str).unwrap_or("unproven"),"classification":finding.get("Classification").or_else(|| finding.get("classification")).and_then(Value::as_str).unwrap_or("unproven"),"evidenceRefs":[]})
}

pub fn denominator_receipt(input: &Value) -> Value {
    json!({"schemaVersion":1,"kind":"legion-secret-denominator","mode":input.get("mode").cloned().unwrap_or(Value::Null),"trackedFiles":input.get("trackedFiles").and_then(Value::as_u64).unwrap_or(0),"untrackedFiles":input.get("untrackedFiles").and_then(Value::as_u64).unwrap_or(0),"ignoredFiles":input.get("ignoredFiles").and_then(Value::as_u64).unwrap_or(0),"generatedFiles":input.get("generatedFiles").and_then(Value::as_u64).unwrap_or(0),"releaseArtifacts":input.get("releaseArtifacts").and_then(Value::as_u64).unwrap_or(0),"historyRefs":input.get("historyRefs").and_then(Value::as_u64).unwrap_or(0)})
}

pub fn analyze(input: &Value) -> Value {
    let evidence = input.get("artifacts").and_then(|a| a.get("secretEvidence"));
    let Some(evidence) = evidence else {
        return json!({"status":"unproven","complete":false,"denominator":{"kind":"secret-scope","expected":0,"examined":0},"findings":[],"coverageGaps":[{"kind":"secret-evidence-missing"}]});
    };
    let receipt = denominator_receipt(evidence.get("denominator").unwrap_or(&Value::Null));
    let mode = receipt
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("current");
    let findings = array(evidence.get("findings"))
        .iter()
        .map(|f| normalize_finding(f, None, None, mode))
        .collect::<Vec<_>>();
    let expected = [
        "trackedFiles",
        "untrackedFiles",
        "ignoredFiles",
        "generatedFiles",
        "releaseArtifacts",
        "historyRefs",
    ]
    .iter()
    .map(|field| receipt.get(field).and_then(Value::as_u64).unwrap_or(0))
    .sum::<u64>();
    let examined = evidence
        .get("examined")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut gaps = Vec::new();
    // This provider promises current files plus history. A current-tree scan
    // can retain useful findings, but file counts (or merely counted refs)
    // cannot attest that commit history was examined.
    let history_examined = matches!(mode, "history" | "current-history")
        && receipt
            .get("historyRefs")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
        && matches!(
            evidence.get("scope").and_then(Value::as_str),
            Some("history" | "current-history")
        )
        && input
            .get("producer")
            .and_then(|p| p.get("scope"))
            .and_then(Value::as_str)
            != Some("current-tree");
    if !history_examined {
        gaps.push(json!({"kind":"secret-history-not-examined"}));
    }
    if evidence
        .get("tool")
        .and_then(|t| t.get("version"))
        .and_then(Value::as_str)
        .is_none_or(|v| v.is_empty())
        || !valid_digest(evidence.get("rulesetDigest"))
    {
        gaps.push(json!({"kind":"secret-tool-or-ruleset-unbound"}));
    }
    if expected == 0 {
        gaps.push(json!({"kind":"secret-denominator-zero"}));
    }
    if examined != expected {
        gaps.push(
            json!({"kind":"secret-denominator-mismatch","expected":expected,"examined":examined}),
        );
    }
    json!({"status":if !gaps.is_empty(){"unproven"}else if !findings.is_empty(){"fail"}else{"pass"},"complete":gaps.is_empty(),"denominator":{"kind":"secret-scope","expected":expected,"examined":examined},"findings":findings,"coverageGaps":gaps})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history_input() -> Value {
        json!({"artifacts":{"secretEvidence":{
            "scope":"current-history",
            "denominator":{"mode":"current-history","trackedFiles":2,"historyRefs":1},
            "examined":3,
            "tool":{"name":"gitleaks","version":"8.18.0"},
            "rulesetDigest":format!("sha256:{}", "a".repeat(64)),
            "findings":[],
        }}})
    }

    fn assert_history_gap(input: &Value) {
        let result = analyze(input);
        assert_eq!(result["complete"], false, "{result}");
        assert_eq!(result["status"], "unproven", "{result}");
        assert!(result["coverageGaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["kind"] == "secret-history-not-examined"));
    }

    #[test]
    fn explicit_history_evidence_with_reconciled_counts_can_complete() {
        let result = analyze(&history_input());
        assert_eq!(result["complete"], true, "{result}");
        assert_eq!(result["status"], "pass");
        assert_eq!(result["denominator"]["expected"], 3);
        assert_eq!(result["denominator"]["examined"], 3);
    }

    #[test]
    fn current_tree_scope_with_counted_refs_cannot_complete_history() {
        let mut input = history_input();
        input["artifacts"]["secretEvidence"]["scope"] = json!("current-tree");
        assert_history_gap(&input);
    }

    #[test]
    fn history_ref_count_without_history_mode_cannot_complete() {
        let mut input = history_input();
        input["artifacts"]["secretEvidence"]["denominator"]["mode"] = json!("current");
        assert_history_gap(&input);
    }

    #[test]
    fn history_mode_without_explicit_scope_cannot_complete() {
        let mut input = history_input();
        input["artifacts"]["secretEvidence"]
            .as_object_mut()
            .unwrap()
            .remove("scope");
        assert_history_gap(&input);
    }

    #[test]
    fn current_tree_producer_cannot_be_relabelled_as_history_evidence() {
        let mut input = history_input();
        input["producer"] = json!({"scope":"current-tree"});
        assert_history_gap(&input);
    }

    #[test]
    fn current_files_do_not_substitute_for_unexamined_history_refs() {
        let mut input = history_input();
        input["artifacts"]["secretEvidence"]["denominator"]["historyRefs"] = json!(0);
        input["artifacts"]["secretEvidence"]["examined"] = json!(2);
        assert_history_gap(&input);
    }
}
