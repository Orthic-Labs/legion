//! Named, offline scanner contracts. Registry selectors select the denominator;
//! producers execute exactly that frozen selection, never a second path filter.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde_json::{json, Value};

use super::common::{digest_json, exact_binding, valid_digest};

pub const TOOLS: &[&str] = &["squawk", "zizmor", "shellcheck", "sqlfluff"];

pub fn tool_for(id: &str) -> Option<&'static str> {
    let tool = id.strip_prefix("security.scanner-")?;
    TOOLS.iter().copied().find(|known| *known == tool)
}

/// Deferred tools are deliberately not advertised as equivalent coverage.
pub fn deferred_tools() -> Value {
    json!({
        "oxlint":"deferred: demonstrate distinct rules/performance beyond configured JS lint before adding overlapping lint"
    })
}

/// Retired donor proposals (issue #39, decision D1). Retirement is not a
/// coverage claim: nothing here is implemented, and no retired tool's rules are
/// represented as covered by another provider.
pub fn retired_tools() -> Value {
    json!({
        "sqllint":"retired: superseded by sqlfluff (Postgres dialect); no Sqllint-equivalent coverage claimed",
        "rubocop":"retired: Ruby removed from retained workloads 2026-10-23; no Ruby lint coverage claimed",
        "checkov":"retired: no demonstrated incremental coverage over retained IaC scanners for retained workloads; no Checkov-equivalent coverage claimed",
        "bandit":"retired: no demonstrated gap beyond configured Python scanners; reopen against concrete uncovered fixtures; no Bandit-equivalent coverage claimed"
    })
}

/// Owned, non-executing SQLFluff configuration. `raw` templater never runs
/// Jinja/dbt/Python templating; `rules` is an explicit allowlist of structural
/// and ambiguity rules, so layout/capitalisation/aliasing style never becomes a
/// candidate. Repository configuration is never loaded (`--ignore-local-config`).
pub const SQLFLUFF_CONFIG: &str = "[sqlfluff]\ndialect = postgres\ntemplater = raw\nencoding = utf-8\ndisable_noqa = True\nprocesses = 1\nrules = AM01, AM02, AM03, AM04, AM06, AM07, RF01, ST03\n";

/// Rule codes (and always-on parse/lex/template violations) SQLFluff may emit
/// under the owned configuration.
const SQLFLUFF_RULES: &[&str] = &[
    "AM01", "AM02", "AM03", "AM04", "AM06", "AM07", "RF01", "ST03",
];
/// Violations meaning the file was not (fully) analyzed, not a lint finding.
const SQLFLUFF_FAILURES: &[&str] = &["PRS", "LXR", "TMP"];

pub fn sqlfluff_args(config: &str, file_args: &[String]) -> Vec<String> {
    [
        "lint",
        "--format",
        "json",
        "--dialect",
        "postgres",
        "--templater",
        "raw",
        "--encoding",
        "utf-8",
        "--config",
        config,
        "--ignore-local-config",
        "--disable-noqa",
        "--disregard-sqlfluffignore",
        "--processes",
        "1",
        "--disable-progress-bar",
        "--",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(file_args.iter().cloned())
    .collect()
}

/// Inline `-- sqlfluff:` directives can rewrite configuration from inside the
/// audited file, so such a file is refused rather than linted.
pub fn sqlfluff_inline_directive(text: &str) -> bool {
    text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .match_indices("--")
            .chain(lower.match_indices("/*"))
            .any(|(at, _)| lower[at + 2..].trim_start().starts_with("sqlfluff:"))
    })
}

/// Exact SQLFluff `--format json` envelope: an array of file records, each an
/// object with a string `filepath` and an array of violation objects.
fn sqlfluff_records(output: &Value) -> Option<Vec<(String, &Vec<Value>)>> {
    output
        .as_array()?
        .iter()
        .map(|record| {
            let path = safe_relative(record.get("filepath")?.as_str()?)?;
            let violations = record.get("violations")?.as_array()?;
            violations
                .iter()
                .all(Value::is_object)
                .then_some((path, violations))
        })
        .collect()
}

fn sqlfluff_code(violation: &Value) -> Option<&str> {
    violation
        .get("code")
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty())
}

/// Violations SQLFluff counts toward a non-zero exit (anything not `warning`).
fn sqlfluff_failing(output: &Value) -> usize {
    sqlfluff_records(output).map_or(0, |records| {
        records
            .iter()
            .flat_map(|(_, violations)| violations.iter())
            .filter(|v| v.get("warning").and_then(Value::as_bool) != Some(true))
            .count()
    })
}

/// Exit status must agree with the report: 0 with failing violations, or 1
/// with none, means the report and process disagree, so neither is trusted.
pub fn sqlfluff_exit_mismatch(output: &Value, exit_code: i64) -> bool {
    let failing = sqlfluff_failing(output);
    (exit_code == 0 && failing > 0) || (exit_code == 1 && failing == 0)
}

/// Per-file accountability for one SQLFluff run. A file is examined only when
/// it has exactly one record and no parse/lex/template violation; every other
/// selected file is a named gap, never clean.
pub fn sqlfluff_examined(output: &Value, selected: &[String]) -> (BTreeSet<String>, Vec<Value>) {
    let mut gaps = Vec::new();
    // Schema failure is reported by `normalize`; nothing is examined.
    let Some(records) = sqlfluff_records(output) else {
        return (BTreeSet::new(), gaps);
    };
    let mut seen: BTreeMap<String, bool> = BTreeMap::new();
    for (path, violations) in records {
        if !selected.contains(&path) {
            gaps.push(
                json!({"kind":"scanner-unexpected-file-record","tool":"sqlfluff","path":path}),
            );
            continue;
        }
        let analyzed = violations
            .iter()
            .all(|v| sqlfluff_code(v).is_some_and(|code| !SQLFLUFF_FAILURES.contains(&code)));
        if seen.insert(path.clone(), analyzed).is_some() {
            gaps.push(
                json!({"kind":"scanner-duplicate-file-record","tool":"sqlfluff","path":path}),
            );
            seen.insert(path, false);
        }
    }
    let mut examined = BTreeSet::new();
    for path in selected {
        match seen.get(path) {
            Some(true) => {
                examined.insert(path.clone());
            }
            Some(false) => {}
            None => gaps
                .push(json!({"kind":"scanner-file-record-missing","tool":"sqlfluff","path":path})),
        }
    }
    (examined, gaps)
}

/// Canonical defaults, mirrored in provider registry & checked below. A plan may
/// narrow these to explicit paths; runtime always uses its frozen selector.
pub fn selector(tool: &str) -> Value {
    match tool {
        "squawk" => json!({"op":"anyExtension","extensions":["sql"]}),
        "shellcheck" => json!({"op":"anyExtension","extensions":["sh","bash","ksh","dash"]}),
        "sqlfluff" => json!({"op":"anyExtension","extensions":["sql"]}),
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
        "sqlfluff" if SQLFLUFF_RULES.contains(&rule) || SQLFLUFF_FAILURES.contains(&rule) => {
            "reliability"
        }
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
    if !matches!(tool, "squawk" | "zizmor" | "shellcheck" | "sqlfluff") {
        report
            .gaps
            .push(json!({"kind":"scanner-unsupported","tool":tool}));
        return report;
    }
    // SQLFluff nests violations under per-file records; flatten each violation
    // with its file so one raw record yields exactly one candidate.
    let flattened: Option<Vec<Value>> = (tool == "sqlfluff").then(|| {
        sqlfluff_records(output)
            .map(|records| {
                records
                    .into_iter()
                    .flat_map(|(path, violations)| {
                        violations.iter().map(move |v| {
                            let mut raw = v.clone();
                            raw["filepath"] = json!(path);
                            raw
                        })
                    })
                    .collect::<Vec<Value>>()
            })
            .unwrap_or_default()
    });
    let values = match output {
        Value::Array(values) if tool != "sqlfluff" => values,
        Value::Array(_) if sqlfluff_records(output).is_some() => {
            flattened.as_ref().expect("sqlfluff flattened")
        }
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
            "sqlfluff" => (
                text_at(raw, "/filepath"),
                raw["start_line_no"].as_u64(),
                text_at(raw, "/code"),
                text_at(raw, "/description"),
                Some(if raw["warning"] == true {
                    "low"
                } else {
                    "medium"
                }),
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
        if (tool == "squawk" && rule == "syntax-error")
            || (tool == "sqlfluff" && SQLFLUFF_FAILURES.contains(&rule.as_str()))
        {
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
    json!({"status":if !candidates.is_empty(){"candidates"}else if classified_only && gaps.is_empty(){"classified"}else if gaps.is_empty(){"pass"}else{"unproven"},"applicable":!files.is_empty(),"complete":valid && gaps.is_empty() && !files.is_empty(),"denominator":{"kind":"scanner-files","expected":files.len(),"examined":examined.len()},"candidates":candidates,"findings":[],"coverageGaps":gaps,"lossLedger":evidence.and_then(|e|e.get("lossLedger")).cloned().unwrap_or_else(||json!([])),"selectionLedger":evidence.and_then(|e|e.get("selectionLedger")).cloned().unwrap_or_else(||json!([])),"classificationOnly":classified_only,"executionMode":if classified_only{"native-classification"}else{"scanner-required"},"deferredTools":deferred_tools(),"retiredTools":retired_tools()})
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
    fn sql_record(path: &str, violations: Value) -> Value {
        json!({"filepath":path,"violations":violations,"statistics":{}})
    }
    fn sql_violation(code: &str, line: u64) -> Value {
        json!({"code":code,"description":"finding","start_line_no":line,"start_line_pos":1,"warning":false,"name":"x","fixes":[]})
    }
    fn selected(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn sqlfluff_clean_report_proves_every_selected_file() {
        let report = json!([
            sql_record("./a.sql", json!([])),
            sql_record("b.sql", json!([]))
        ]);
        let (examined, gaps) = sqlfluff_examined(&report, &selected(&["a.sql", "b.sql"]));
        assert_eq!(examined.len(), 2);
        assert!(gaps.is_empty());
        assert!(!sqlfluff_exit_mismatch(&report, 0));
        assert!(normalize("sqlfluff", &report, Path::new("/repo"), "")
            .candidates
            .is_empty());
    }

    #[test]
    fn sqlfluff_parse_lex_and_template_errors_are_gaps_never_clean() {
        for code in ["PRS", "LXR", "TMP"] {
            let report = json!([sql_record("a.sql", json!([sql_violation(code, 3)]))]);
            let (examined, _) = sqlfluff_examined(&report, &selected(&["a.sql"]));
            assert!(examined.is_empty(), "{code}");
            let normalized = normalize("sqlfluff", &report, Path::new("/repo"), "");
            assert!(
                normalized
                    .gaps
                    .iter()
                    .any(|gap| gap["kind"] == "scanner-parser-failed"),
                "{code}"
            );
            assert_eq!(normalized.candidates.len(), 1);
            assert_eq!(normalized.candidates[0]["domain"], "reliability");
        }
    }

    #[test]
    fn sqlfluff_missing_duplicate_and_unexpected_records_are_named_gaps() {
        let report = json!([
            sql_record("a.sql", json!([])),
            sql_record("a.sql", json!([])),
            sql_record("other.sql", json!([]))
        ]);
        let (examined, gaps) = sqlfluff_examined(&report, &selected(&["a.sql", "b.sql"]));
        assert!(examined.is_empty());
        for kind in [
            "scanner-duplicate-file-record",
            "scanner-unexpected-file-record",
            "scanner-file-record-missing",
        ] {
            assert!(gaps.iter().any(|gap| gap["kind"] == kind), "{kind}");
        }
    }

    #[test]
    fn sqlfluff_invalid_envelopes_prove_nothing() {
        for bad in [
            json!({}),
            json!(null),
            json!([{"filepath":"a.sql"}]),
            json!([{"violations":[]}]),
            json!([{"filepath":"../a.sql","violations":[]}]),
            json!([{"filepath":"a.sql","violations":[1]}]),
            json!(["a.sql"]),
        ] {
            let (examined, _) = sqlfluff_examined(&bad, &selected(&["a.sql"]));
            assert!(examined.is_empty(), "{bad}");
            let normalized = normalize("sqlfluff", &bad, Path::new("/repo"), "");
            assert!(
                normalized
                    .gaps
                    .iter()
                    .any(|gap| gap["kind"] == "scanner-output-schema-invalid"),
                "{bad}"
            );
        }
    }

    #[test]
    fn sqlfluff_violation_without_code_is_not_examined_and_unresolved() {
        let report = json!([sql_record(
            "a.sql",
            json!([{"description":"x","start_line_no":1,"warning":false}])
        )]);
        let (examined, _) = sqlfluff_examined(&report, &selected(&["a.sql"]));
        assert!(examined.is_empty());
        let normalized = normalize("sqlfluff", &report, Path::new("/repo"), "");
        assert_eq!(normalized.candidates[0]["anchorStatus"], "unresolved");
    }

    #[test]
    fn sqlfluff_exit_status_must_agree_with_report() {
        let finding = json!([sql_record("a.sql", json!([sql_violation("AM04", 2)]))]);
        let clean = json!([sql_record("a.sql", json!([]))]);
        assert!(sqlfluff_exit_mismatch(&finding, 0));
        assert!(!sqlfluff_exit_mismatch(&finding, 1));
        assert!(sqlfluff_exit_mismatch(&clean, 1));
        assert!(!sqlfluff_exit_mismatch(&clean, 0));
    }

    #[test]
    fn sqlfluff_findings_keep_one_based_lines_and_known_rule_domains() {
        let report = json!([sql_record("m.sql", json!([sql_violation("AM04", 7)]))]);
        let normalized = normalize("sqlfluff", &report, Path::new("/repo"), "");
        assert_eq!(normalized.candidates[0]["line"], 7);
        assert_eq!(normalized.candidates[0]["path"], "m.sql");
        assert_eq!(normalized.candidates[0]["ruleId"], "AM04");
        assert_eq!(normalized.candidates[0]["domain"], "reliability");
        assert!(normalized.gaps.is_empty());
        assert_eq!(candidate_domain("sqlfluff", "LT01"), "unknown");
    }

    #[test]
    fn sqlfluff_command_pins_postgres_owned_config_and_never_nofail() {
        let args = sqlfluff_args("/scratch/cfg", &["./a.sql".into()]);
        let joined = args.join(" ");
        for required in [
            "lint",
            "--dialect postgres",
            "--templater raw",
            "--config /scratch/cfg",
            "--ignore-local-config",
            "--disable-noqa",
            "--disregard-sqlfluffignore",
            "--format json",
        ] {
            assert!(joined.contains(required), "{required}");
        }
        assert!(!joined.contains("--nofail"));
        assert_eq!(&args[args.len() - 2..], ["--", "./a.sql"]);
        assert!(SQLFLUFF_CONFIG.contains("dialect = postgres"));
        assert!(SQLFLUFF_CONFIG.contains("templater = raw"));
    }

    #[test]
    fn sqlfluff_inline_config_directives_are_detected() {
        assert!(sqlfluff_inline_directive(
            "select 1;\n-- sqlfluff:dialect:mysql\n"
        ));
        assert!(sqlfluff_inline_directive(
            "/* SQLFluff: rules:all */ select 1;"
        ));
        assert!(!sqlfluff_inline_directive(
            "-- plain comment about sqlfluff\nselect 1;"
        ));
    }

    #[test]
    fn retired_donors_state_reasons_without_claiming_equivalent_coverage() {
        let retired = retired_tools();
        for tool in ["sqllint", "rubocop", "checkov", "bandit"] {
            let reason = retired[tool].as_str().unwrap();
            assert!(reason.starts_with("retired:"), "{tool}");
            assert!(
                reason.contains("no ") && reason.contains("claimed"),
                "{tool}"
            );
        }
        assert!(deferred_tools().get("sqlfluff").is_none());
    }
}
