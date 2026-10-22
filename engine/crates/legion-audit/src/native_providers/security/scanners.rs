//! Named, offline scanner contracts. Registry selectors select the denominator;
//! producers execute exactly that frozen selection, never a second path filter.
use std::path::{Component, Path};

use serde_json::{json, Value};

use super::common::{digest_json, exact_binding, valid_digest};

pub const TOOLS: &[&str] = &["squawk", "zizmor", "shellcheck"];

pub fn tool_for(id: &str) -> Option<&'static str> {
    let tool = id.strip_prefix("security.scanner-")?;
    TOOLS.iter().copied().find(|known| *known == tool)
}

/// Deferred tools are deliberately not advertised as equivalent coverage.
pub fn deferred_tools() -> Value {
    json!({
        "sqllint":"deferred: dialect/connection scope not established; squawk covers migration safety, not SQL semantic validity",
        "sqlfluff":"deferred: project dialect & policy required; formatting is not migration safety",
        "rubocop":"deferred: project Ruby policy & safe configuration required; Brakeman covers Rails security, not Ruby lint",
        "checkov":"deferred: demonstrate distinct rules beyond Trivy before adding overlapping IaC scan",
        "bandit":"deferred: demonstrate Python rule gaps beyond configured Semgrep before adding overlapping SAST",
        "oxlint":"deferred: demonstrate distinct rules/performance beyond configured JS lint before adding overlapping lint"
    })
}

/// Canonical defaults, mirrored in provider registry & checked below. A plan may
/// narrow these to explicit paths; runtime always uses its frozen selector.
pub fn selector(tool: &str) -> Value {
    match tool {
        "squawk" => json!({"op":"anyExtension","extensions":["sql"]}),
        "shellcheck" => json!({"op":"anyExtension","extensions":["sh","bash","ksh","dash"]}),
        "zizmor" => {
            json!({"op":"anyPath","patterns":[".github/workflows/*.yml",".github/workflows/*.yaml","**/.github/workflows/*.yml","**/.github/workflows/*.yaml","action.yml","action.yaml","**/action.yml","**/action.yaml",".github/dependabot.yml",".github/dependabot.yaml"]})
        }
        _ => Value::Null,
    }
}

pub fn safe_relative(raw: &str) -> Option<String> {
    let text = raw.replace('\\', "/");
    let path = Path::new(&text);
    if path.is_absolute()
        || text.contains(':')
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    let text = text.trim_start_matches("./");
    (!text.is_empty()).then(|| text.to_owned())
}

#[derive(Default, Debug)]
pub struct Normalized {
    pub candidates: Vec<Value>,
    pub gaps: Vec<Value>,
    pub ledger: Vec<Value>,
}

fn text_at<'a>(raw: &'a Value, pointer: &str) -> Option<&'a str> {
    raw.pointer(pointer)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

/// Route scanner claims by documented rule semantics. Unknown/new categories
/// remain unknown rather than inheriting security from provider namespace.
pub fn candidate_domain(tool: &str, rule: &str) -> &'static str {
    match tool {
        "squawk"
            if matches!(
                rule,
                "ban-drop-column"
                    | "ban-drop-table"
                    | "ban-drop-database"
                    | "ban-drop-not-null"
                    | "changing-column-type"
                    | "renaming-column"
                    | "renaming-table"
                    | "adding-required-field"
                    | "adding-foreign-key-constraint"
                    | "constraint-missing-not-valid"
                    | "require-concurrent-index-creation"
                    | "require-concurrent-index-deletion"
                    | "require-lock-timeout"
                    | "require-statement-timeout"
                    | "require-timeout-settings"
                    | "prefer-robust-stmts"
                    | "prefer-repack"
                    | "require-enum-value-ordering"
            ) =>
        {
            "data"
        }
        "squawk" if rule == "syntax-error" => "reliability",
        "shellcheck"
            if rule.strip_prefix("SC").is_some_and(|code| {
                !code.is_empty() && code.chars().all(|c| c.is_ascii_digit())
            }) =>
        {
            "reliability"
        }
        "zizmor"
            if matches!(
                rule,
                "template-injection"
                    | "artipacked"
                    | "cache-poisoning"
                    | "dangerous-triggers"
                    | "excessive-permissions"
                    | "github-env"
                    | "impostor-commit"
                    | "known-vulnerable-actions"
                    | "ref-confusion"
                    | "secrets-inherit"
                    | "self-hosted-runner"
                    | "unpinned-uses"
                    | "unpinned-images"
                    | "use-trusted-publishing"
                    | "bot-conditions"
                    | "anonymous-definition"
                    | "obfuscation"
                    | "overprovisioned-secrets"
                    | "unredacted-secrets"
                    | "unsound-contains"
            ) =>
        {
            "security"
        }
        _ => "unknown",
    }
}

/// Every raw entry has exactly one ledger row. Unlocated/malformed entries stay
/// candidates with unknown anchors, so normalization cannot erase scanner recall.
pub fn normalize(tool: &str, output: &Value, root: &Path, base: &str) -> Normalized {
    let mut report = Normalized::default();
    if !matches!(tool, "squawk" | "zizmor" | "shellcheck") {
        report
            .gaps
            .push(json!({"kind":"scanner-unsupported","tool":tool}));
        return report;
    }
    let values = match output {
        Value::Array(values) => values,
        _ => {
            let raw_digest = digest_json(output);
            let id = digest_json(&json!([tool, base, "invalid-schema", raw_digest]));
            report.gaps.push(json!({"kind":"scanner-output-schema-invalid","tool":tool,"rawOutputDigest":raw_digest}));
            report.candidates.push(json!({"id":id,"ruleId":format!("{tool}.output-unresolved"),"domain":"unknown","path":Value::Null,"line":Value::Null,"claim":"Scanner output schema changed; retain raw result for inspection","severityHint":"unknown","anchorStatus":"unresolved","source":{"tool":tool,"rawFindingDigest":raw_digest,"raw":output},"evidence":[{"rawFindingDigest":raw_digest}]}));
            report.ledger.push(json!({"rawFindingDigest":raw_digest,"candidateId":id,"disposition":"retained-unresolved-output"}));
            return report;
        }
    };
    for (ordinal, raw) in values.iter().enumerate() {
        let mut location = raw;
        if tool == "zizmor" {
            location = raw
                .get("locations")
                .and_then(Value::as_array)
                .and_then(|locations| {
                    locations
                        .iter()
                        .find(|v| text_at(v, "/symbolic/kind") == Some("Primary"))
                })
                .unwrap_or(&Value::Null);
        }
        let (file, line, rule, message, severity) = match tool {
            "squawk" => (
                text_at(raw, "/file"),
                raw["line"].as_u64().and_then(|v| v.checked_add(1)),
                text_at(raw, "/rule_name"),
                text_at(raw, "/message"),
                Some("medium"),
            ),
            "zizmor" => (
                text_at(location, "/symbolic/key/Local/verbatim_path"),
                location
                    .pointer("/concrete/location/start_point/row")
                    .and_then(Value::as_u64)
                    .and_then(|v| v.checked_add(1)),
                text_at(raw, "/ident"),
                text_at(raw, "/desc"),
                text_at(raw, "/determinations/severity"),
            ),
            "shellcheck" => (
                text_at(raw, "/file"),
                raw["line"].as_u64(),
                None,
                text_at(raw, "/message"),
                text_at(raw, "/level"),
            ),
            _ => unreachable!(),
        };
        let raw_digest = digest_json(raw);
        let path = file.and_then(|file| {
            let path = Path::new(file);
            if path.is_absolute() {
                path.strip_prefix(root)
                    .ok()
                    .and_then(|p| safe_relative(&p.to_string_lossy()))
            } else {
                safe_relative(&if base.is_empty() {
                    file.to_owned()
                } else {
                    format!("{base}/{file}")
                })
            }
        });
        let rule = if tool == "shellcheck" {
            raw["code"].as_u64().map(|code| format!("SC{code}"))
        } else {
            rule.map(str::to_owned)
        };
        let unresolved = path.is_none()
            || line.filter(|v| *v > 0).is_none()
            || rule.is_none()
            || message.is_none();
        let rule = rule.unwrap_or_else(|| format!("{tool}.unknown"));
        let message = message.unwrap_or("Scanner record requires source inspection");
        let domain = candidate_domain(tool, &rule);
        if domain == "unknown" {
            report.gaps.push(json!({"kind":"scanner-candidate-domain-unresolved","tool":tool,"ruleId":rule,"rawFindingDigest":raw_digest}));
        }
        let candidate = json!({
            "id":digest_json(&json!([tool,base,ordinal,raw_digest])),
            "ruleId":rule,"claim":message,"title":message,"path":path,
            "line":line.filter(|v| *v>0),"severityHint":severity.unwrap_or("unknown"),
            "domain":domain,"adjudication":"required",
            "anchorKind":if line.is_some() {"line"} else {"unknown"},
            "evidence":[{"path":path,"line":line,"rawFindingDigest":raw_digest}],
            "source":{"tool":tool,"ruleId":rule,"rawFindingDigest":raw_digest,"recordOrdinal":ordinal,"raw":raw},
            "anchorStatus":if unresolved {"unresolved"} else {"scanner-reported"},
        });
        if unresolved {
            report.gaps.push(json!({"kind":"scanner-candidate-anchor-unresolved","tool":tool,"rawFindingDigest":raw_digest}));
        }
        if tool == "squawk" && rule == "syntax-error" {
            report.gaps.push(
                json!({"kind":"scanner-parser-failed","tool":tool,"rawFindingDigest":raw_digest}),
            );
        }
        report.ledger.push(json!({"ordinal":ordinal,"rawFindingDigest":raw_digest,"path":path,"candidateId":candidate["id"],"disposition":if unresolved {"retained-unresolved"} else {"candidate"}}));
        report.candidates.push(candidate);
    }
    report
}

pub fn analyze(input: &Value) -> Value {
    let files: Vec<String> = super::common::files(input.get("projection"));
    let evidence = input.pointer("/artifacts/scannerEvidence");
    let mut gaps = evidence
        .and_then(|e| e.get("gaps"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Registry selection fixes provider applicability. Native classification
    // settles entries only with explicit source-bound evidence, never a claim
    // that a scanner executed successfully.
    let envelope_valid = evidence.is_some_and(|e| {
        exact_binding(e.get("binding"), input.pointer("/plan/binding"))
            && e.get("selectedPaths") == Some(&json!(files))
    });
    let native_paths: std::collections::BTreeSet<String> = evidence
        .and_then(|e| e.get("selectionLedger"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|row| {
            row["disposition"] == "not-applicable"
                && valid_digest(row.get("sourceDigest"))
                && matches!(
                    row["reason"].as_str(),
                    Some("deleted-source-has-no-selected-tool-input")
                )
        })
        .filter_map(|row| row["path"].as_str())
        .filter(|path| files.iter().any(|p| p == path))
        .map(str::to_owned)
        .collect();
    let classified_only = evidence.is_some_and(|e| {
        e.get("applicablePaths")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
            && native_paths.len() == files.len()
    });
    let receipt_valid = evidence.is_some_and(|e| {
        e.pointer("/executionReceipt/complete")
            .and_then(Value::as_bool)
            == Some(true)
            && e.pointer("/executionReceipt/offline")
                .and_then(Value::as_bool)
                == Some(true)
            && valid_digest(e.pointer("/executionReceipt/tool/executableDigest"))
    });
    let valid = envelope_valid && (classified_only || receipt_valid);
    if !valid && !files.is_empty() {
        gaps.push(json!({"kind":"scanner-evidence-invalid"}));
    }
    let examined: Vec<String> = evidence
        .and_then(|e| e.get("examinedPaths"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|path| {
            envelope_valid
                && files.iter().any(|p| p == path)
                && (receipt_valid || native_paths.contains(*path))
        })
        .map(str::to_owned)
        .collect();
    let examined: std::collections::BTreeSet<_> = examined.into_iter().collect();
    for path in &files {
        if !examined.contains(path) {
            gaps.push(json!({"kind":"scanner-input-unexamined","path":path}));
        }
    }
    let candidates = evidence
        .and_then(|e| e.get("candidates"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({"status":if !candidates.is_empty(){"candidates"}else if classified_only && gaps.is_empty(){"classified"}else if gaps.is_empty(){"pass"}else{"unproven"},"applicable":!files.is_empty(),"complete":valid && gaps.is_empty() && !files.is_empty(),"denominator":{"kind":"scanner-files","expected":files.len(),"examined":examined.len()},"candidates":candidates,"findings":[],"coverageGaps":gaps,"lossLedger":evidence.and_then(|e|e.get("lossLedger")).cloned().unwrap_or_else(||json!([])),"selectionLedger":evidence.and_then(|e|e.get("selectionLedger")).cloned().unwrap_or_else(||json!([])),"classificationOnly":classified_only,"executionMode":if classified_only{"native-classification"}else{"scanner-required"},"deferredTools":deferred_tools()})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_match_registry_selection_authority() {
        let registry: Value = serde_json::from_str(include_str!(
            "../../../../../../src/registry/providers.json"
        ))
        .unwrap();
        for tool in TOOLS {
            let id = format!("security.scanner-{tool}");
            let provider = registry["providers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["id"] == id)
                .unwrap();
            assert_eq!(provider["selector"], selector(tool));
            assert_eq!(tool_for(&id), Some(*tool));
        }
    }
    #[test]
    fn zero_based_sql_and_workflow_lines_become_one_based() {
        let sql = normalize(
            "squawk",
            &json!([{"file":"m.sql","line":0,"rule_name":"ban-drop-column","message":"data loss"}]),
            Path::new("/repo"),
            "",
        );
        assert_eq!(sql.candidates[0]["line"], 1);
        assert_eq!(sql.ledger.len(), 1);
        let workflow = normalize(
            "zizmor",
            &json!([{"ident":"template-injection","desc":"injection","locations":[{"symbolic":{"kind":"Primary","key":{"Local":{"verbatim_path":".github/workflows/test.yml"}}},"concrete":{"location":{"start_point":{"row":3}}}}]}]),
            Path::new("/repo"),
            "",
        );
        assert_eq!(workflow.candidates[0]["line"], 4);
    }
    #[test]
    fn malformed_outside_and_fixture_records_never_disappear() {
        let report = normalize(
            "shellcheck",
            &json!([null,{"file":"../../secret","line":2,"code":2086,"message":"quote"},{"file":"fixtures/secrets.sh","line":1,"code":2086,"message":"fixture"}]),
            Path::new("/repo"),
            "",
        );
        assert_eq!(report.candidates.len(), 3);
        assert_eq!(report.ledger.len(), 3);
        assert_eq!(report.candidates[1]["path"], Value::Null);
        assert_eq!(report.candidates[2]["path"], "fixtures/secrets.sh");
        assert!(!report.gaps.is_empty());
    }
    #[test]
    fn malformed_schema_is_never_clean() {
        let report = normalize("squawk", &json!({}), Path::new("/repo"), "");
        assert!(!report.gaps.is_empty());
        assert_eq!(report.candidates.len(), 1);
    }

    #[test]
    fn unlocated_records_stay_unresolved_without_inventing_lines() {
        let shell = normalize(
            "shellcheck",
            &json!([{"file":"run.sh","code":2086,"message":"quote"}]),
            Path::new("/repo"),
            "",
        );
        assert_eq!(shell.candidates[0]["anchorKind"], "unknown");
        assert_eq!(shell.candidates[0]["anchorStatus"], "unresolved");
        assert!(shell
            .gaps
            .iter()
            .any(|gap| gap["kind"] == "scanner-candidate-anchor-unresolved"));
    }

    #[test]
    fn every_named_adapter_preserves_rule_source_and_loss_ledger() {
        let cases = [
            (
                "squawk",
                json!([{"file":"m.sql","line":0,"rule_name":"ban-drop-column","message":"data loss"}]),
            ),
            (
                "zizmor",
                json!([{"ident":"template-injection","desc":"injection","locations":[{"symbolic":{"kind":"Primary","key":{"Local":{"verbatim_path":".github/workflows/ci.yml"}}},"concrete":{"location":{"start_point":{"row":1}}}}]}]),
            ),
            (
                "shellcheck",
                json!([{"file":"run.sh","line":2,"code":2086,"message":"quote expansion"}]),
            ),
        ];
        for (tool, output) in cases {
            let report = normalize(tool, &output, Path::new("/repo"), "");
            assert_eq!(report.candidates.len(), 1, "{tool}");
            assert_eq!(report.ledger.len(), 1, "{tool}");
            assert_eq!(report.candidates[0]["source"]["tool"], tool);
            assert_eq!(
                report.candidates[0]["domain"],
                candidate_domain(tool, report.candidates[0]["ruleId"].as_str().unwrap())
            );
            assert!(valid_digest(
                report.candidates[0].pointer("/source/rawFindingDigest")
            ));
        }
    }
    #[test]
    fn mixed_scanner_categories_do_not_inherit_security_namespace() {
        assert_eq!(candidate_domain("squawk", "ban-drop-column"), "data");
        assert_eq!(candidate_domain("shellcheck", "SC2086"), "reliability");
        assert_eq!(candidate_domain("shellcheck", "not-a-code"), "unknown");
        assert_eq!(candidate_domain("squawk", "new-rule"), "unknown");
    }
}
