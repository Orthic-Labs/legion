//! Port of src/lib/pr/scope.mjs.

use super::sha256_prefixed;
use serde_json::{json, Value};

pub fn changed_files(merge_base: &str, committed: &[String], uncommitted: &[String], untracked: &[String]) -> Value {
    let mut committed = committed.to_vec();
    committed.sort();
    let mut uncommitted = uncommitted.to_vec();
    uncommitted.sort();
    let mut untracked = untracked.to_vec();
    untracked.sort();
    json!({
        "mergeBase": merge_base,
        "committed": committed,
        "uncommitted": uncommitted,
        "untracked": untracked,
    })
}

pub fn classify_finding_scope(finding: &Value, changed_paths: &[String]) -> &'static str {
    let Some(file) = finding.get("file").and_then(Value::as_str) else {
        return "existing";
    };
    let file = file.replace('\\', "/");
    let introduced = changed_paths.iter().any(|path| {
        let normalized = path.replace('\\', "/");
        let normalized = normalized.trim_end_matches('/');
        file == normalized || file.starts_with(&format!("{normalized}/"))
    });
    if introduced { "introduced" } else { "existing" }
}

pub fn pr_scope_result(findings: &[Value], changed_paths: &[String], full_coverage: &Value) -> Value {
    let classified: Vec<Value> = findings
        .iter()
        .map(|finding| {
            let mut merged = finding.clone();
            if let Value::Object(ref mut map) = merged {
                map.insert("scope".into(), json!(classify_finding_scope(finding, changed_paths)));
            }
            merged
        })
        .collect();
    let introduced: Vec<Value> = classified.iter().filter(|f| f["scope"] == "introduced").cloned().collect();
    let existing: Vec<Value> = classified.iter().filter(|f| f["scope"] == "existing").cloned().collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-pr-scope",
        "introduced": introduced,
        "existing": existing,
        "fullCoverage": full_coverage,
        "providersNotRun": [],
        "note": "PR mode reports new blockers by default while preserving backlog visibility.",
    })
}

pub fn stable_comment_id(finding: &Value) -> String {
    let key = finding
        .get("fingerprint")
        .or_else(|| finding.get("id"))
        .or_else(|| finding.get("ruleId"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    sha256_prefixed("pr-comment", &json!(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_finding_scope_matches_directory_prefix() {
        let finding = json!({"file": "src/lib/host/index.mjs"});
        assert_eq!(classify_finding_scope(&finding, &["src/lib/host/".to_string()]), "introduced");
        assert_eq!(classify_finding_scope(&finding, &["src/lib/policy/".to_string()]), "existing");
    }

    #[test]
    fn classify_finding_scope_defaults_existing_without_file() {
        let finding = json!({});
        assert_eq!(classify_finding_scope(&finding, &["anything".to_string()]), "existing");
    }

    #[test]
    fn pr_scope_result_partitions_introduced_and_existing() {
        let findings = vec![
            json!({"file": "src/a.mjs"}),
            json!({"file": "src/b.mjs"}),
        ];
        let result = pr_scope_result(&findings, &["src/a.mjs".to_string()], &json!({"ok": true}));
        assert_eq!(result["introduced"].as_array().unwrap().len(), 1);
        assert_eq!(result["existing"].as_array().unwrap().len(), 1);
        assert_eq!(result["fullCoverage"]["ok"], true);
    }

    #[test]
    fn stable_comment_id_is_deterministic() {
        let finding = json!({"fingerprint": "fp1"});
        assert_eq!(stable_comment_id(&finding), stable_comment_id(&finding));
    }
}
