//! Named, offline scanner contracts. Registry selectors select the denominator;
//! producers execute exactly that frozen selection, never a second path filter.
use std::path::{Component, Path};

use serde_json::{json, Value};

use super::common::{digest_json, exact_binding, valid_digest};

pub const TOOLS: &[&str] = &[
    "squawk",
    "zizmor",
    "shellcheck",
    "tflint",
    "kubeconform",
    "kube-linter",
    "brakeman",
    "golangci-lint",
];

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
        "tflint" => json!({"op":"anyPath","patterns":["**/*.tf","**/*.tf.json"]}),
        "kubeconform" | "kube-linter" => {
            json!({"op":"anyExtension","extensions":["yml","yaml","json"]})
        }
        "brakeman" => {
            json!({"op":"anyExtension","extensions":["rb","rake","erb","haml","slim","gemspec"]})
        }
        "golangci-lint" => json!({"op":"anyExtension","extensions":["go"]}),
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
        "tflint"
            if matches!(
                rule,
                "terraform_unused_declarations"
                    | "terraform_deprecated_interpolation"
                    | "terraform_deprecated_index"
                    | "terraform_empty_list_equality"
                    | "terraform_module_pinned_source"
                    | "terraform_module_version"
                    | "terraform_required_providers"
                    | "terraform_required_version"
                    | "terraform_documented_outputs"
                    | "terraform_documented_variables"
                    | "terraform_typed_variables"
            ) =>
        {
            "reliability"
        }
        "kubeconform" if rule == "schema" => "reliability",
        "kube-linter"
            if matches!(
                rule,
                "privileged-container"
                    | "privilege-escalation-container"
                    | "host-network"
                    | "host-pid"
                    | "host-ipc"
                    | "sensitive-host-mounts"
                    | "wildcard-in-rules"
                    | "cluster-admin-role-binding"
                    | "writable-host-mount"
                    | "unsafe-proc-mount"
                    | "run-as-non-root"
                    | "no-read-only-root-fs"
            ) =>
        {
            "security"
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
        // Brakeman's warning/check namespace is Rails SAST, not Ruby style lint.
        "brakeman" if !rule.is_empty() && !rule.ends_with(".unknown") => "security",
        "golangci-lint" if rule == "gosec" => "security",
        "golangci-lint"
            if matches!(
                rule,
                "typecheck"
                    | "govet"
                    | "staticcheck"
                    | "errcheck"
                    | "ineffassign"
                    | "unused"
                    | "bodyclose"
                    | "nilerr"
                    | "nilnil"
                    | "errorlint"
                    | "rowserrcheck"
                    | "sqlclosecheck"
            ) =>
        {
            "reliability"
        }
        _ => "unknown",
    }
}

/// Every raw entry has exactly one ledger row. Unlocated/malformed entries stay
/// candidates with unknown anchors, so normalization cannot erase scanner recall.
pub fn normalize(tool: &str, output: &Value, root: &Path, base: &str) -> Normalized {
    let mut report = Normalized::default();
    let key = match tool {
        "squawk" | "zizmor" | "shellcheck" => None,
        "tflint" => Some("issues"),
        "kubeconform" => Some("resources"),
        "kube-linter" => Some("Reports"),
        "brakeman" => Some("warnings"),
        "golangci-lint" => Some("Issues"),
        _ => {
            report
                .gaps
                .push(json!({"kind":"scanner-unsupported","tool":tool}));
            return report;
        }
    };
    let values = key.map_or(Some(output), |key| output.get(key));
    // golangci explicitly reports Issues:null when no issues exist.
    let empty = Vec::new();
    let values = match values {
        Some(Value::Array(values)) => values,
        Some(Value::Null) if tool == "golangci-lint" => &empty,
        // kube-linter v0.8.3 pkg/run/run.go leaves Reports nil when no
        // diagnostics exist. Its JSON formatter therefore emits null, with
        // an explicit Passed summary & populated enabled-check list.
        Some(Value::Null)
            if tool == "kube-linter"
                && output
                    .pointer("/Summary/ChecksStatus")
                    .and_then(Value::as_str)
                    == Some("Passed")
                && output
                    .get("Checks")
                    .and_then(Value::as_array)
                    .is_some_and(|checks| !checks.is_empty()) =>
        {
            &empty
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
            "shellcheck" => (
                text_at(raw, "/file"),
                raw["line"].as_u64(),
                None,
                text_at(raw, "/message"),
                text_at(raw, "/level"),
            ),
            "tflint" => (
                text_at(raw, "/range/filename"),
                raw.pointer("/range/start/line").and_then(Value::as_u64),
                text_at(raw, "/rule/name"),
                text_at(raw, "/message"),
                text_at(raw, "/rule/severity"),
            ),
            "kubeconform" => (
                text_at(raw, "/filename"),
                None,
                Some("schema"),
                text_at(raw, "/msg"),
                Some("medium"),
            ),
            "kube-linter" => (
                text_at(raw, "/Object/Metadata/FilePath"),
                None,
                text_at(raw, "/Check"),
                text_at(raw, "/Diagnostic/Message"),
                Some("medium"),
            ),
            "brakeman" => (
                text_at(raw, "/file"),
                raw["line"].as_u64(),
                text_at(raw, "/check_name"),
                text_at(raw, "/message"),
                Some("medium"),
            ),
            "golangci-lint" => (
                text_at(raw, "/Pos/Filename"),
                raw.pointer("/Pos/Line").and_then(Value::as_u64),
                text_at(raw, "/FromLinter"),
                text_at(raw, "/Text"),
                Some("medium"),
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
        let valid_resource =
            tool == "kubeconform" && text_at(raw, "/status") == Some("statusValid");
        if valid_resource && path.is_some() {
            report.ledger.push(json!({"ordinal":ordinal,"rawFindingDigest":raw_digest,"path":path,"disposition":"resource-valid"}));
            continue;
        }
        let rule = if tool == "shellcheck" {
            raw["code"].as_u64().map(|code| format!("SC{code}"))
        } else {
            rule.map(str::to_owned)
        };
        let unresolved = path.is_none()
            || line.filter(|v| *v > 0).is_none()
            || rule.is_none()
            || message.is_none();
        // These tools report resources/files, not source lines. Keep their
        // anchor unresolved until producer binds it to scanned frozen bytes.
        let file_anchor = (tool == "kube-linter"
            || (tool == "kubeconform" && text_at(raw, "/status") == Some("statusInvalid")))
            && path.is_some()
            && rule.is_some()
            && message.is_some();
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
            "anchorKind":if file_anchor {"file"} else if line.is_some() {"line"} else {"unknown"},
            "evidence":[{"path":path,"line":line,"rawFindingDigest":raw_digest}],
            "source":{"tool":tool,"ruleId":rule,"rawFindingDigest":raw_digest,"recordOrdinal":ordinal,"raw":raw},
            "anchorStatus":if unresolved {"unresolved"} else {"scanner-reported"},
        });
        if unresolved {
            report.gaps.push(json!({"kind":"scanner-candidate-anchor-unresolved","tool":tool,"rawFindingDigest":raw_digest}));
        }
        if tool == "golangci-lint" && rule == "typecheck" {
            report.gaps.push(json!({"kind":"scanner-typecheck-failed","tool":tool,"rawFindingDigest":raw_digest}));
        }
        if tool == "squawk" && rule == "syntax-error" {
            report.gaps.push(
                json!({"kind":"scanner-parser-failed","tool":tool,"rawFindingDigest":raw_digest}),
            );
        }
        if tool == "kubeconform" && text_at(raw, "/status") != Some("statusInvalid") {
            report.gaps.push(json!({"kind":"scanner-schema-unavailable-or-error","tool":tool,"rawFindingDigest":raw_digest}));
        }
        report.ledger.push(json!({"ordinal":ordinal,"rawFindingDigest":raw_digest,"path":path,"candidateId":candidate["id"],"disposition":if unresolved {"retained-unresolved"} else {"candidate"}}));
        report.candidates.push(candidate);
    }
    for error_key in match tool {
        "tflint" => &["errors"][..],
        "brakeman" => &["errors"][..],
        _ => &[][..],
    } {
        if output
            .get(*error_key)
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty())
        {
            report.gaps.push(json!({"kind":"scanner-analysis-errors","tool":tool,"errorDigest":digest_json(&output[*error_key])}));
        }
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
                    Some(
                        "no-kubernetes-object-identity"
                            | "deleted-source-has-no-selected-tool-input"
                    )
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
    fn malformed_schema_is_gap_and_go_typecheck_is_never_clean() {
        assert!(!normalize("brakeman", &json!({}), Path::new("/repo"), "")
            .gaps
            .is_empty());
        let go = normalize(
            "golangci-lint",
            &json!({"Issues":[{"FromLinter":"typecheck","Text":"cannot load","Pos":{"Filename":"x.go","Line":1}}]}),
            Path::new("/repo"),
            "",
        );
        assert_eq!(go.candidates.len(), 1);
        assert!(go
            .gaps
            .iter()
            .any(|g| g["kind"] == "scanner-typecheck-failed"));
    }

    #[test]
    fn kube_linter_nil_reports_require_passed_summary_and_enabled_checks() {
        // Documented upstream zero-diagnostic Result; normalization alone
        // grants no execution or coverage claim without producer receipts.
        let clean = json!({
            "Checks":[{"Name":"privileged-container"}],
            "Reports":null,
            "Summary":{"ChecksStatus":"Passed","KubeLinterVersion":"0.8.3"}
        });
        let report = normalize("kube-linter", &clean, Path::new("/repo"), "");
        assert!(report.candidates.is_empty());
        assert!(report.gaps.is_empty());
        assert!(report.ledger.is_empty());

        for invalid in [
            json!({"Reports":null}),
            json!({"Reports":null,"Checks":[],"Summary":{"ChecksStatus":"Passed"}}),
            json!({"Reports":null,"Checks":[{}],"Summary":{"ChecksStatus":"Failed"}}),
            json!({"Reports":null,"Checks":[{}],"Summary":{"ChecksStatus":"Unknown"}}),
            json!({"Checks":[{}],"Summary":{"ChecksStatus":"Passed"}}),
            json!({"Reports":{},"Checks":[{}],"Summary":{"ChecksStatus":"Passed"}}),
        ] {
            let report = normalize("kube-linter", &invalid, Path::new("/repo"), "");
            assert_eq!(report.candidates.len(), 1, "{invalid}");
            assert_eq!(report.ledger.len(), 1, "{invalid}");
            assert!(
                report
                    .gaps
                    .iter()
                    .any(|gap| gap["kind"] == "scanner-output-schema-invalid"),
                "{invalid}"
            );
        }
    }

    #[test]
    fn kube_file_anchors_wait_for_source_binding_without_inventing_lines() {
        for (tool, output) in [
            (
                "kubeconform",
                json!({"resources":[{"filename":"pod.yaml","status":"statusInvalid","msg":"schema mismatch"}]}),
            ),
            (
                "kube-linter",
                json!({"Reports":[{"Check":"privileged-container","Object":{"Metadata":{"FilePath":"pod.yaml"}},"Diagnostic":{"Message":"privileged"}}]}),
            ),
        ] {
            let report = normalize(tool, &output, Path::new("/repo"), "");
            assert_eq!(report.candidates.len(), 1);
            let candidate = &report.candidates[0];
            assert_eq!(candidate["anchorKind"], "file");
            assert_eq!(candidate["anchorStatus"], "unresolved");
            assert!(candidate["line"].is_null());
            assert!(candidate["evidence"][0]["line"].is_null());
            assert_eq!(candidate["adjudication"], "required");
            assert_eq!(report.ledger[0]["disposition"], "retained-unresolved");
            assert!(report
                .gaps
                .iter()
                .any(|gap| gap["kind"] == "scanner-candidate-anchor-unresolved"));
        }
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
        let error = normalize(
            "kubeconform",
            &json!({"resources":[{"filename":"pod.yaml","status":"statusError","msg":"schema unavailable"}]}),
            Path::new("/repo"),
            "",
        );
        assert_eq!(error.candidates[0]["anchorKind"], "unknown");
        assert!(error
            .gaps
            .iter()
            .any(|gap| gap["kind"] == "scanner-schema-unavailable-or-error"));
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
            (
                "tflint",
                json!({"issues":[{"rule":{"name":"terraform_unused_declarations"},"range":{"filename":"main.tf","start":{"line":3}},"message":"unused"}]}),
            ),
            (
                "kubeconform",
                json!({"resources":[{"filename":"pod.yaml","status":"statusInvalid","msg":"schema mismatch"}]}),
            ),
            (
                "kube-linter",
                json!({"Reports":[{"Check":"privileged-container","Object":{"Metadata":{"FilePath":"pod.yaml"}},"Diagnostic":{"Message":"privileged"}}]}),
            ),
            (
                "brakeman",
                json!({"warnings":[{"file":"app/model.rb","line":4,"check_name":"SQL","message":"SQL injection"}]}),
            ),
            (
                "golangci-lint",
                json!({"Issues":[{"FromLinter":"gosec","Text":"unsafe permissions","Pos":{"Filename":"main.go","Line":5}}]}),
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
        assert_eq!(
            candidate_domain("tflint", "terraform_unused_declarations"),
            "reliability"
        );
        assert_eq!(candidate_domain("kubeconform", "schema"), "reliability");
        assert_eq!(candidate_domain("golangci-lint", "gosec"), "security");
        assert_eq!(candidate_domain("golangci-lint", "govet"), "reliability");
        assert_eq!(candidate_domain("golangci-lint", "new-linter"), "unknown");
        assert_eq!(
            candidate_domain("tflint", "terraform_naming_convention"),
            "unknown"
        );
        let report = normalize(
            "golangci-lint",
            &json!({"Issues":[
                {"FromLinter":"gosec","Text":"tainted input","Pos":{"Filename":"a.go","Line":1}},
                {"FromLinter":"govet","Text":"bad format","Pos":{"Filename":"a.go","Line":2}},
                {"FromLinter":"new-linter","Text":"unclassified","Pos":{"Filename":"a.go","Line":3}}
            ]}),
            Path::new("/repo"),
            "",
        );
        assert_eq!(
            report
                .candidates
                .iter()
                .map(|c| c["domain"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["security", "reliability", "unknown"]
        );
        assert!(report
            .gaps
            .iter()
            .any(|gap| gap["kind"] == "scanner-candidate-domain-unresolved"));
    }
}
