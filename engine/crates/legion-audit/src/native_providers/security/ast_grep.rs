use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{digest, files, path, string};

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

pub fn stable_fingerprint(
    rule_id: &str,
    file: Option<&str>,
    range: &Value,
    structural_digest: Option<&str>,
) -> String {
    super::common::digest(format!("ast-grep-match\0{}", serde_json::to_string(&json!({"ruleId":rule_id,"file":file,"range":range,"structuralDigest":structural_digest})).unwrap_or_default()).as_bytes())
}

pub fn normalize_match(
    line: &Value,
    rule_id: &str,
    provider: Option<&str>,
    severity: Option<&str>,
) -> Value {
    let file = path(line);
    let range = line.get("range").cloned().unwrap_or_else(|| json!({"start":{"line":line.get("line").or_else(||line.get("start").and_then(|v|v.get("line"))).and_then(Value::as_u64).unwrap_or(1),"column":line.get("column").or_else(||line.get("start").and_then(|v|v.get("column"))).and_then(Value::as_u64).unwrap_or(0)},"end":{"line":line.get("end").and_then(|v|v.get("line")).or_else(||line.get("line")).and_then(Value::as_u64).unwrap_or(1),"column":line.get("end").and_then(|v|v.get("column")).or_else(||line.get("column")).and_then(Value::as_u64).unwrap_or(0)}}));
    let effective_rule = string(line.get("ruleId")).unwrap_or_else(|| rule_id.into());
    json!({"ruleId":effective_rule,"severity":string(line.get("severity")).unwrap_or_else(||severity.unwrap_or("warning").into()),"message":string(line.get("message").or_else(||line.get("note"))).unwrap_or_else(||rule_id.into()),"file":file,"range":range,"metavariables":line.get("metavariables").or_else(||line.get("meta")).cloned().unwrap_or_else(||json!({})),"fingerprint":stable_fingerprint(&effective_rule,file.as_deref(),&range,string(line.get("structuralDigest").or_else(||line.get("digest"))).as_deref()),"rawArtifactRef":line.get("rawArtifactRef").cloned().unwrap_or(Value::Null),"provider":provider.unwrap_or("ast-grep.structural")})
}

pub fn normalize_stream(lines: &[Value], rule_id: &str) -> Vec<Value> {
    lines
        .iter()
        .map(|line| normalize_match(line, rule_id, None, None))
        .filter(|line| line.get("file").is_some_and(|v| !v.is_null()))
        .collect()
}

pub fn command_contract(
    resolved: impl Into<String>,
    pack: impl Into<String>,
    frozen_paths: &[String],
    root: impl Into<String>,
    policy: Option<&Value>,
) -> CommandContract {
    let root = root.into();
    let mut args = vec![
        "scan".into(),
        "--config".into(),
        pack.into(),
        "--json=stream".into(),
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

pub fn rewrite_preview(rule_id: &str, file: &str, edits: &[Value]) -> Value {
    let edits=edits.iter().map(|edit|json!({"startLine":edit.get("startLine"),"endLine":edit.get("endLine"),"replacement":edit.get("replacement"),"digest":digest(edit.get("replacement").and_then(Value::as_str).unwrap_or_default().as_bytes())})).collect::<Vec<_>>();
    json!({"schemaVersion":1,"kind":"legion-ast-grep-rewrite-preview","ruleId":rule_id,"file":file,"edits":edits,"applied":false,"note":"preview only; application is governed by isolated-worktree remediation"})
}

pub fn capability_receipt(executable: &str, version: Option<&str>, languages: &[String]) -> Value {
    let mut langs = languages.to_vec();
    langs.sort();
    langs.dedup();
    json!({"schemaVersion":1,"kind":"legion-ast-grep-capability","executable":executable,"version":version,"languages":langs})
}

pub fn analyze(input: &Value) -> Value {
    let mut paths = files(input.get("projection"))
        .into_iter()
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    let examined = input
        .get("artifacts")
        .and_then(|a| a.get("examinedPaths"))
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    let unexamined = paths
        .iter()
        .filter(|p| !examined.contains(p.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let unsupported = super::common::array(
        input
            .get("artifacts")
            .and_then(|a| a.get("unsupportedGrammars")),
    );
    let mut gaps = Vec::new();
    if paths.is_empty() {
        gaps.push(json!({"kind":"structural-denominator-zero"}));
    }
    if input
        .get("artifacts")
        .and_then(|a| a.get("astGrepTool"))
        .is_none()
    {
        gaps.push(json!({"kind":"structural-tool-unqualified"}));
    }
    if !unexamined.is_empty() {
        gaps.push(json!({"kind":"structural-denominator-incomplete","unexamined":unexamined}));
    }
    for grammar in unsupported {
        gaps.push(json!({"kind":"unsupported-grammar","grammar":grammar}));
    }
    json!({"status":if gaps.is_empty(){"pass"}else{"unproven"},"complete":gaps.is_empty(),"denominator":{"kind":"sealed-source-paths","expected":paths.len(),"examined":paths.len()-unexamined.len(),"unexamined":unexamined},"findings":[],"candidates":super::common::array(input.get("artifacts").and_then(|a|a.get("structuralMatches"))),"coverageGaps":gaps})
}
