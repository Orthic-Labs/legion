//! Diff-bound anti-suppression candidates. Presence of a legitimate unchanged
//! exclusion is not a defect; only newly broadened rule/target coverage is raised.
use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::{json, Value};

use super::{
    common::{digest, digest_json, exact_binding},
    scanners::safe_relative,
};

pub fn selector() -> Value {
    json!({"op":"always"})
}

#[derive(Debug)]
struct Directive {
    tool: String,
    rules: Vec<String>,
    context: String,
    line: usize,
}

/// Lex comment text while excluding ordinary strings. This intentionally does
/// not claim language-parser completeness: unknown syntax remains reviewable
/// through config-change candidates & caller's diff coverage.
fn comments(text: &str) -> Vec<(usize, String, String)> {
    let lines: Vec<_> = text.lines().collect();
    let mut out = Vec::new();
    let mut block = false;
    for (index, line) in lines.iter().enumerate() {
        let chars: Vec<_> = line.char_indices().collect();
        let mut quote = None;
        let mut escaped = false;
        let mut start = None;
        let mut i = 0;
        while i < chars.len() {
            let (offset, c) = chars[i];
            let next = chars.get(i + 1).map(|(_, c)| *c);
            if block {
                start.get_or_insert(offset);
                if c == '*' && next == Some('/') {
                    block = false;
                }
            } else if let Some(delimiter) = quote {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == delimiter {
                    quote = None;
                }
            } else if matches!(c, '\'' | '"' | '`') {
                quote = Some(c);
            } else if c == '#' || (c == '/' && next == Some('/')) || (c == '-' && next == Some('-'))
            {
                start = Some(offset);
                break;
            } else if c == '/' && next == Some('*') {
                start = Some(offset);
                block = true;
                i += 1;
            }
            i += 1;
        }
        if let Some(offset) = start {
            let code = line[..offset].trim();
            let context = if !code.is_empty() {
                code.to_owned()
            } else {
                lines
                    .iter()
                    .skip(index + 1)
                    .map(|line| line.trim())
                    .find(|line| !line.is_empty() && !line.starts_with(['#', '/', '*', '-']))
                    .unwrap_or("")
                    .to_owned()
            };
            out.push((
                index + 1,
                line[offset..].to_owned(),
                digest(context.as_bytes()),
            ));
        }
    }
    out
}

fn directives(text: &str) -> Vec<Directive> {
    // Rule IDs are retained rather than treating every marker as blanket disable.
    let patterns = [
        ("semgrep", r"(?i)\bnosemgrep\b\s*:?\s*([a-z0-9_.:, -]*)"),
        ("bandit", r"(?i)\bnosec\b\s*:?\s*([a-z0-9_, -]*)"),
        ("ruff", r"(?i)\bnoqa\b\s*:?\s*([a-z0-9_, -]*)"),
        (
            "shellcheck",
            r"(?i)\bshellcheck\s+disable\s*=\s*([a-z0-9_, -]+)",
        ),
        (
            "squawk",
            r"(?i)\bsquawk-ignore(?:-start)?\b\s*:?\s*([a-z0-9_, -]*)",
        ),
        ("golangci-lint", r"(?i)\bnolint\b\s*:?\s*([a-z0-9_, -]*)"),
        ("zizmor", r"(?i)\bzizmor\s*:\s*ignore\[([^\]]*)\]"),
        ("checkov", r"(?i)\bcheckov\s*:\s*skip\s*=\s*([a-z0-9_]+)"),
        ("tflint", r"(?i)\btflint-ignore\b\s*:?\s*([a-z0-9_, -]*)"),
        ("gitleaks", r"(?i)\bgitleaks\s*:\s*allow\b([a-z0-9_]*)"),
    ];
    let patterns: Vec<_> = patterns
        .into_iter()
        .map(|(tool, pattern)| (tool, Regex::new(pattern).expect("fixed suppression regex")))
        .collect();
    let mut directives = Vec::new();
    for (line, comment, context) in comments(text) {
        for (tool, pattern) in &patterns {
            for found in pattern.captures_iter(&comment) {
                let payload = found.get(1).map(|v| v.as_str()).unwrap_or("");
                // Spaces in prose are not rule IDs. Comma-separated rule tokens
                // cover actual scanners; a marker without IDs means all rules.
                let rules: Vec<_> = payload
                    .split(',')
                    .filter_map(|part| part.split_whitespace().next())
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                directives.push(Directive {
                    tool: (*tool).into(),
                    rules: if rules.is_empty() {
                        vec!["*".into()]
                    } else {
                        rules
                    },
                    context: context.clone(),
                    line,
                });
            }
        }
    }
    // Kubernetes suppressions are mapping keys, not comments. Retain per-check
    // suffix so ignoring one check is distinct from blanket ignore-all.
    let annotations=Regex::new(r#"(?:ignore-check\.kube-linter\.io/|ignore\.kube-linter\.io/)([A-Za-z0-9_-]+)["']?\s*:\s*(?:['"]?)([^\r\n]*)"#).expect("fixed annotation regex");
    for (index, line) in text.lines().enumerate() {
        if let Some(found) = annotations.captures(line) {
            directives.push(Directive {
                tool: "kube-linter".into(),
                rules: vec![found[1].to_owned()],
                context: digest(found[2].trim().as_bytes()),
                line: index + 1,
            });
        }
    }
    directives
}

fn config_tool(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if name.contains("semgrep") || name.contains("opengrep") {
        Some("semgrep")
    } else if name.contains("gitleaks") {
        Some("gitleaks")
    } else if name.contains("zizmor") {
        Some("zizmor")
    } else if name.contains("squawk") {
        Some("squawk")
    } else if name.contains("tflint") {
        Some("tflint")
    } else if name.contains("kube-linter") {
        Some("kube-linter")
    } else if name.contains("golangci") {
        Some("golangci-lint")
    } else if name.contains("brakeman") {
        Some("brakeman")
    } else if name.contains("rubocop") {
        Some("rubocop")
    } else if name.contains("ruff") {
        Some("ruff")
    } else if name.contains("bandit") {
        Some("bandit")
    } else if name.contains("eslint") || name.starts_with("biome.") || name.contains("oxlint") {
        Some("javascript-lint")
    } else if matches!(name.as_str(), "deny.toml" | ".deny.toml") {
        Some("cargo-deny")
    } else if name.contains("sqlfluff") {
        Some("sqlfluff")
    } else if name == ".shellcheckrc" {
        Some("shellcheck")
    } else {
        None
    }
}

/// Shared project manifests also hold unrelated package settings. Inspect only
/// scanner policy subtrees, so ordinary dependency/version changes do not become
/// blanket policy candidates.
fn manifest_policy(path: &str, text: &str) -> Option<(String, Value)> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name == "pyproject.toml" {
        let value = text.parse::<toml::Value>().ok()?;
        let tool = value.get("tool");
        let projection = json!({"ruff":tool.and_then(|v|v.get("ruff")),"bandit":tool.and_then(|v|v.get("bandit")),"semgrep":tool.and_then(|v|v.get("semgrep")),"sqlfluff":tool.and_then(|v|v.get("sqlfluff"))});
        Some(("python-sql-lint".into(), projection))
    } else if name == "Cargo.toml" {
        let value = text.parse::<toml::Value>().ok()?;
        Some((
            "rust-lint".into(),
            json!({"lints":value.get("lints"),"workspaceLints":value.get("workspace").and_then(|v|v.get("lints"))}),
        ))
    } else if name == "package.json" {
        let value: Value = serde_json::from_str(text).ok()?;
        Some((
            "javascript-lint".into(),
            json!({"eslintConfig":value.get("eslintConfig"),"standard":value.get("standard"),"jshintConfig":value.get("jshintConfig")}),
        ))
    } else {
        None
    }
}

fn suppression_domain(tool: &str, rule: &str) -> &'static str {
    match tool {
        "gitleaks" | "bandit" | "brakeman" => "security",
        "ruff"
            if rule.starts_with('S')
                && rule[1..].chars().all(|c| c.is_ascii_digit())
                && rule.len() > 1 =>
        {
            "security"
        }
        "ruff"
            if (rule.starts_with('F') || rule.starts_with('B'))
                && rule[1..].chars().all(|c| c.is_ascii_digit())
                && rule.len() > 1 =>
        {
            "reliability"
        }
        _ => super::scanners::candidate_domain(tool, rule),
    }
}

fn candidate(
    path: &str,
    line: usize,
    tool: &str,
    rule: &str,
    kind: &str,
    before: &str,
    after: &str,
) -> Value {
    let source = json!({"tool":tool,"ruleId":rule,"beforeDigest":digest(before.as_bytes()),"afterDigest":digest(after.as_bytes()),"kind":"source-diff"});
    let claim = if kind == "suppression-rule-added" {
        "Changed suppression broadens scanner exclusions; verify rule & target justification"
    } else {
        "Scanner policy changed; verify removed rules, exclusions & severity weakening"
    };
    let domain = suppression_domain(tool, rule);
    json!({"id":digest_json(&json!([path,line,tool,rule,kind,source])),"ruleId":kind,"suppressedRuleId":rule,"domain":domain,"path":path,"line":line,"title":claim,"claim":claim,"severityHint":"medium","adjudication":"required","evidence":[{"path":path,"line":line,"beforeDigest":source["beforeDigest"],"afterDigest":source["afterDigest"]}],"source":source})
}

/// Expected input: {binding:{repositoryRevision,digest},files:[{path,before,
/// after}]}. Missing before/after is a coverage gap, never an unchanged file.
pub fn changes(input: &Value, binding: &Value, paths: &[String]) -> Value {
    let mut candidates = Vec::new();
    let mut gaps = input
        .get("gaps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut examined = BTreeSet::new();
    let mut ledger = Vec::new();
    if !exact_binding(input.get("binding"), Some(binding)) {
        gaps.push(json!({"kind":"suppression-diff-binding-invalid"}));
    } else if let Some(files) = input.get("files").and_then(Value::as_array) {
        let mut seen = BTreeSet::new();
        for file in files {
            let Some(path) = file
                .get("path")
                .and_then(Value::as_str)
                .and_then(safe_relative)
            else {
                gaps.push(json!({"kind":"suppression-diff-path-invalid"}));
                continue;
            };
            if !paths.contains(&path) || !seen.insert(path.clone()) {
                gaps.push(json!({"kind":"suppression-diff-path-outside-or-duplicate","path":path}));
                continue;
            }
            let (Some(before), Some(after)) = (
                file.get("before").and_then(Value::as_str),
                file.get("after").and_then(Value::as_str),
            ) else {
                gaps.push(json!({"kind":"suppression-diff-content-missing","path":path}));
                continue;
            };
            if before.len() > 2 * 1024 * 1024 || after.len() > 2 * 1024 * 1024 {
                gaps.push(json!({"kind":"suppression-diff-oversize","path":path}));
                continue;
            }
            examined.insert(path.clone());
            let candidate_start = candidates.len();
            let mut prior: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
            for directive in directives(before) {
                prior
                    .entry((directive.tool, directive.context))
                    .or_default()
                    .extend(directive.rules);
            }
            for directive in directives(after) {
                for rule in directive.rules {
                    let unchanged = prior
                        .get(&(directive.tool.clone(), directive.context.clone()))
                        .is_some_and(|rules| rules.contains("*") || rules.contains(&rule));
                    ledger.push(json!({"path":path,"line":directive.line,"tool":directive.tool,"rule":rule,"disposition":if unchanged{"unchanged-exclusion"}else{"candidate"}}));
                    if !unchanged {
                        candidates.push(candidate(
                            &path,
                            directive.line,
                            &directive.tool,
                            &rule,
                            "suppression-rule-added",
                            before,
                            after,
                        ));
                    }
                }
            }
            if let Some(tool) = config_tool(&path) {
                // Ignore whitespace/comment-only changes; meaningful policy
                // changes remain candidates rather than asserted weakening.
                let semantic = |text: &str| {
                    text.lines()
                        .map(str::trim)
                        .filter(|line| {
                            !line.is_empty() && !line.starts_with('#') && !line.starts_with("//")
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                if semantic(before) != semantic(after) {
                    candidates.push(candidate(
                        &path,
                        1,
                        tool,
                        "policy-change",
                        "scanner-policy-changed",
                        before,
                        after,
                    ));
                }
            }
            let policy_before = manifest_policy(&path, before);
            let policy_after = manifest_policy(&path, after);
            if policy_before.as_ref().map(|(_, value)| value)
                != policy_after.as_ref().map(|(_, value)| value)
            {
                let tool = policy_after
                    .as_ref()
                    .or(policy_before.as_ref())
                    .map(|(tool, _)| tool.as_str())
                    .unwrap_or("unknown-scanner");
                candidates.push(candidate(
                    &path,
                    1,
                    tool,
                    "manifest-policy-change",
                    "scanner-policy-changed",
                    before,
                    after,
                ));
            }
            let source_side = file
                .get("sourceSide")
                .and_then(Value::as_str)
                .filter(|side| matches!(*side, "base" | "selected"))
                .unwrap_or("selected");
            for candidate in &mut candidates[candidate_start..] {
                if candidate["domain"] == "unknown" {
                    gaps.push(json!({"kind":"suppression-candidate-domain-unresolved","path":path,"candidateId":candidate["id"]}));
                }
                candidate["sourceSide"] = json!(source_side);
                candidate["source"]["sourceSide"] = json!(source_side);
                candidate["evidence"][0]["sourceSide"] = json!(source_side);
            }
        }
    } else {
        gaps.push(json!({"kind":"suppression-diff-files-missing"}));
    }
    // Unchanged paths need explicit source proof, supplied separately; absence
    // from a diff list alone does not prove this frozen snapshot was compared.
    if let Some(unchanged) = input.get("unchangedPaths").and_then(Value::as_array) {
        for path in unchanged.iter().filter_map(Value::as_str) {
            if paths.iter().any(|p| p == path) {
                examined.insert(path.to_owned());
            } else {
                gaps.push(json!({"kind":"suppression-unchanged-path-outside","path":path}));
            }
        }
    }
    for path in paths {
        if !examined.contains(path) {
            gaps.push(json!({"kind":"suppression-baseline-unexamined","path":path}));
        }
    }
    json!({"binding":binding,"selectedPaths":paths,"examinedPaths":examined,"candidates":candidates,"gaps":gaps,"lossLedger":ledger})
}

pub fn analyze(input: &Value) -> Value {
    let paths = super::common::files(input.get("projection"));
    let evidence = input.pointer("/artifacts/suppressionEvidence");
    let valid = evidence.is_some_and(|e| {
        exact_binding(e.get("binding"), input.pointer("/plan/binding"))
            && e.get("selectedPaths") == Some(&json!(paths))
    });
    let mut gaps = evidence
        .and_then(|e| e.get("gaps"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !valid {
        gaps.push(json!({"kind":"suppression-evidence-invalid"}));
    }
    let examined = evidence
        .and_then(|e| e.get("examinedPaths"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let candidates = evidence
        .and_then(|e| e.get("candidates"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({"status":if !candidates.is_empty(){"candidates"}else{"unproven"},"complete":valid&&gaps.is_empty()&&examined==paths.len()&&!paths.is_empty(),"applicable":!paths.is_empty(),"denominator":{"kind":"suppression-source-files","expected":paths.len(),"examined":if valid{examined}else{0}},"candidates":candidates,"findings":[],"coverageGaps":gaps,"lossLedger":evidence.and_then(|e|e.get("lossLedger")).cloned().unwrap_or_else(||json!([]))})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inspect(before: &str, after: &str) -> Value {
        let binding = json!({"repositoryRevision":"abc","digest":"digest"});
        changes(
            &json!({"binding":binding,"files":[{"path":"fixtures/app.py","before":before,"after":after}]}),
            &binding,
            &["fixtures/app.py".into()],
        )
    }
    #[test]
    fn unchanged_legitimate_exclusion_is_not_blanket_finding() {
        let report = inspect("x = 1 # noqa: F401\n", "x = 1 # noqa: F401\n");
        assert_eq!(report["candidates"], json!([]));
    }
    #[test]
    fn added_rule_broadening_and_fixture_suppressions_survive() {
        let report = inspect("x = 1 # noqa: F401\n", "x = 1 # noqa: F401, S101\n");
        assert_eq!(report["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(report["candidates"][0]["suppressedRuleId"], "S101");
        assert_eq!(report["candidates"][0]["path"], "fixtures/app.py");
    }
    #[test]
    fn strings_and_narrowed_blanket_suppressions_do_not_raise() {
        assert_eq!(inspect("", "s = '# noqa: S101'\n")["candidates"], json!([]));
        assert_eq!(
            inspect("x = 1 # noqa\n", "x = 1 # noqa: S101\n")["candidates"],
            json!([])
        );
    }
    #[test]
    fn missing_or_wrong_revision_baseline_is_gap() {
        let report = changes(
            &json!({"binding":{},"files":[]}),
            &json!({"digest":"other"}),
            &["app.py".into()],
        );
        assert!(!report["gaps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn manifest_dependency_changes_do_not_mask_or_fake_lint_policy_changes() {
        let binding = json!({"repositoryRevision":"abc","digest":"digest"});
        let paths = vec!["pyproject.toml".into()];
        let run = |before: &str, after: &str| {
            changes(
                &json!({"binding":binding,"files":[{"path":"pyproject.toml","before":before,"after":after}]}),
                &binding,
                &paths,
            )
        };
        assert_eq!(
            run("[project]\nversion = '1'\n", "[project]\nversion = '2'\n")["candidates"],
            json!([])
        );
        assert_eq!(
            run(
                "[tool.ruff.lint]\nignore = []\n",
                "[tool.ruff.lint]\nignore = ['S101']\n"
            )["candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn suppression_domains_follow_suppressed_rule_not_provider_name() {
        assert_eq!(suppression_domain("ruff", "S101"), "security");
        assert_eq!(suppression_domain("ruff", "F821"), "reliability");
        assert_eq!(suppression_domain("shellcheck", "SC2086"), "reliability");
        assert_eq!(suppression_domain("squawk", "ban-drop-column"), "data");
        assert_eq!(suppression_domain("python-sql-lint", "*"), "unknown");
        assert_eq!(suppression_domain("golangci-lint", "gosec"), "security");
        assert_eq!(suppression_domain("golangci-lint", "govet"), "reliability");
    }
}
