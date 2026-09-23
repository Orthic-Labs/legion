//! Port of `editorDiagnostics` from `src/lib/report/editor/index.mjs`.
//!
//! Editor diagnostics per SNIP-HTML-01's editor surface. Emits stable
//! diagnostics/code-action preview JSON; LSP transport is a thin process
//! around this artifact. See `tests/report/editor.test.mjs` in the JS tree
//! for the ported JS test coverage.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A remediation patch. `digest` is checked against the qualification
/// regex; the rest of the object (JS spreads the whole `patch` value onto
/// the code action) is preserved via `#[serde(flatten)]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemediationPatch {
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// A finding's proposed remediation, matching JS's
/// `finding.remediation.{id,qualified,patch,findingFingerprint,findingIds}`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Remediation {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub qualified: Option<bool>,
    #[serde(default)]
    pub patch: Option<RemediationPatch>,
    #[serde(default, rename = "findingFingerprint")]
    pub finding_fingerprint: Option<String>,
    #[serde(default, rename = "findingIds")]
    pub finding_ids: Option<Vec<String>>,
}

/// `finding.lineage`, when the caller supplies one explicitly (JS passes
/// this object through verbatim rather than reconstructing it).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Lineage {
    pub state: String,
    #[serde(default, rename = "priorContentId")]
    pub prior_content_id: Option<String>,
    #[serde(default, rename = "contentId")]
    pub content_id: Option<String>,
}

/// One input finding, matching the fields `editorDiagnostics` reads off
/// `report.findings[i]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, rename = "ruleId")]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<i64>,
    #[serde(default)]
    pub column: Option<i64>,
    #[serde(default, rename = "endLine")]
    pub end_line: Option<i64>,
    #[serde(default, rename = "endColumn")]
    pub end_column: Option<i64>,
    /// Passed through verbatim when present (JS uses `finding.range ?? {...}`
    /// as-is, never rebuilding a caller-supplied range).
    #[serde(default)]
    pub range: Option<Value>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default, rename = "evidenceClass")]
    pub evidence_class: Option<String>,
    #[serde(default, rename = "evidenceRefs")]
    pub evidence_refs: Vec<Value>,
    #[serde(default, rename = "contentId")]
    pub content_id: Option<String>,
    #[serde(default, rename = "staleContentId")]
    pub stale_content_id: Option<String>,
    #[serde(default)]
    pub lineage: Option<Lineage>,
    #[serde(default)]
    pub remediation: Option<Remediation>,
}

/// One input coverage gap, matching `report.coverage_gaps[i]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageGapInput {
    #[serde(default, rename = "reviewRequired")]
    pub review_required: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
}

/// `{ findings, coverage_gaps }`, matching JS's `report?.findings ?? []`
/// and `report?.coverage_gaps ?? []`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportInput {
    #[serde(default)]
    pub findings: Vec<FindingInput>,
    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGapInput>,
}

/// `editorDiagnostics`'s `{ report, runDir }` argument. `report: None`
/// mirrors the JS optional-chained `report?.findings` (a missing report).
#[derive(Debug, Clone, Default)]
pub struct EditorInput {
    pub report: Option<ReportInput>,
    pub run_dir: Option<String>,
}

/// A rendered diagnostic. Kept as raw JSON (matching the untyped JS object
/// literal) since findings and coverage-gap diagnostics have different
/// optional shapes (only gap diagnostics carry `coverageIncomplete`).
pub type EditorDiagnostic = Value;

fn sha256_digest_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^sha256:[0-9a-f]{64}$").expect("valid regex"))
}

/// `severityFor`: `critical`/`high` -> 1 (error), `medium` -> 2 (warning),
/// anything else (including absent) -> 3 (info).
fn severity_for(severity: Option<&str>) -> i64 {
    match severity {
        Some("critical") | Some("high") => 1,
        Some("medium") => 2,
        _ => 3,
    }
}

/// `!finding.remediation?.findingFingerprint || finding.remediation.findingFingerprint === finding.fingerprint`.
fn fingerprint_bound(finding: &FindingInput, remediation: &Remediation) -> bool {
    match &remediation.finding_fingerprint {
        None => true,
        Some(ff) if ff.is_empty() => true,
        Some(ff) => Some(ff.as_str()) == finding.fingerprint.as_deref(),
    }
}

/// `finding.remediation?.qualified === true && sha256-digest-regex.test(patch.digest ?? '')
/// && (findingIds ?? [finding.id]).includes(finding.id) && fingerprintBound`.
fn remediation_bound(finding: &FindingInput) -> bool {
    let Some(remediation) = &finding.remediation else {
        return false;
    };
    if remediation.qualified != Some(true) {
        return false;
    }
    let digest = remediation
        .patch
        .as_ref()
        .and_then(|p| p.digest.clone())
        .unwrap_or_default();
    if !sha256_digest_re().is_match(&digest) {
        return false;
    }
    // `(findingIds ?? [finding.id]).includes(finding.id)`: with no explicit
    // findingIds, the JS default array trivially contains finding.id.
    let finding_ids_include = match &remediation.finding_ids {
        None => true,
        Some(ids) => finding
            .id
            .as_deref()
            .map(|fid| ids.iter().any(|i| i == fid))
            .unwrap_or(false),
    };
    if !finding_ids_include {
        return false;
    }
    fingerprint_bound(finding, remediation)
}

/// `finding.range ?? { start: {...}, end: {...} }`.
fn range_for(finding: &FindingInput) -> Value {
    if let Some(range) = &finding.range {
        return range.clone();
    }
    let start_line = finding.line.unwrap_or(1);
    let start_column = finding.column.unwrap_or(0);
    let end_line = finding.end_line.or(finding.line).unwrap_or(1);
    let end_column = finding.end_column.or(finding.column).unwrap_or(0);
    json!({
        "start": { "line": start_line, "column": start_column },
        "end": { "line": end_line, "column": end_column },
    })
}

fn range_field_i64(range: &Value, field: &str) -> Option<i64> {
    range.get("start").and_then(|s| s.get(field)).and_then(Value::as_i64)
}

fn finding_diagnostic(finding: &FindingInput, run_dir: Option<&str>) -> Value {
    let range = range_for(finding);
    let line = range_field_i64(&range, "line").unwrap_or_else(|| finding.line.unwrap_or(1));
    let column = range_field_i64(&range, "column").unwrap_or_else(|| finding.column.unwrap_or(0));

    let file = finding.file.as_deref().map(|f| f.replace('\\', "/"));

    let message = match (&finding.title, &finding.detail) {
        (Some(title), Some(detail)) => format!("{title} — {detail}"),
        (Some(title), None) => title.clone(),
        (None, _) => finding
            .detail
            .clone()
            .unwrap_or_else(|| "Legion finding".to_string()),
    };

    let code = finding
        .rule_id
        .clone()
        .unwrap_or_else(|| "legion.finding".to_string());

    let fingerprint = finding
        .fingerprint
        .clone()
        .or_else(|| finding.id.clone())
        .or_else(|| finding.rule_id.clone());

    let lineage = match &finding.lineage {
        Some(l) => json!({
            "state": l.state,
            "priorContentId": l.prior_content_id,
            "contentId": l.content_id,
        }),
        None => {
            let state = if finding.stale_content_id.is_some() {
                "stale"
            } else {
                "current"
            };
            json!({
                "state": state,
                "priorContentId": finding.stale_content_id,
                "contentId": finding.content_id,
            })
        }
    };

    let mut code_actions: Vec<Value> = Vec::new();
    if finding.id.is_some() || finding.rule_id.is_some() {
        if remediation_bound(finding) {
            let remediation = finding.remediation.as_ref().expect("bound implies present");
            code_actions.push(json!({
                "title": "Preview Legion remediation",
                "kind": "preview",
                "previewOnly": true,
                "proposalId": remediation.id,
                "findingId": finding.id,
                "fingerprint": finding.fingerprint,
                "patch": remediation.patch.as_ref().map(|p| serde_json::to_value(p).unwrap_or(Value::Null)),
            }));
        }
        code_actions.push(json!({
            "title": "Explain with Legion",
            "kind": "explain",
            "id": finding.id.clone().or_else(|| finding.rule_id.clone()),
        }));
    }

    json!({
        "schemaVersion": 1,
        "kind": "legion-editor-diagnostic",
        "file": file,
        "range": range,
        "line": line,
        "column": column,
        "severity": severity_for(finding.severity.as_deref()),
        "code": code,
        "message": message,
        "fingerprint": fingerprint,
        "findingId": finding.id,
        "family": finding.family,
        "evidenceClass": finding.evidence_class,
        "explanation": {
            "kind": "legion-finding-explanation",
            "findingId": finding.id,
            "evidenceRefs": finding.evidence_refs,
        },
        "contentId": finding.content_id,
        "lineage": lineage,
        "run": run_dir,
        "codeActions": code_actions,
    })
}

fn gap_diagnostic(gap: &CoverageGapInput, run_dir: Option<&str>) -> Value {
    let kind_str = gap.kind.clone().unwrap_or_else(|| "undefined".to_string());
    let fingerprint = gap
        .id
        .clone()
        .unwrap_or_else(|| format!("gap:{kind_str}"));
    let message = gap
        .detail
        .clone()
        .or_else(|| gap.kind.clone())
        .unwrap_or_else(|| "Incomplete coverage".to_string());

    json!({
        "schemaVersion": 1,
        "kind": "legion-editor-diagnostic",
        "file": Value::Null,
        "range": Value::Null,
        "severity": 2,
        "code": "legion.coverage-gap",
        "message": message,
        "fingerprint": fingerprint,
        "findingId": Value::Null,
        "family": gap.family,
        "evidenceClass": "missing",
        "explanation": { "kind": "legion-gap-explanation", "gapId": gap.id },
        "lineage": { "state": "current" },
        "run": run_dir,
        "codeActions": Value::Array(vec![]),
        "coverageIncomplete": true,
    })
}

/// Faithful port of `editorDiagnostics({ report, runDir })`: maps
/// `report.findings` to stable, line-independent diagnostics (fingerprint
/// is the identity; `line`/`column` are a convenience projection), then
/// appends one diagnostic per `report.coverage_gaps` entry whose
/// `reviewRequired` is true, in that order.
pub fn editor_diagnostics(input: &EditorInput) -> Vec<EditorDiagnostic> {
    let run_dir = input.run_dir.as_deref();
    let empty = ReportInput::default();
    let report = input.report.as_ref().unwrap_or(&empty);

    let mut out: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| finding_diagnostic(finding, run_dir))
        .collect();

    out.extend(
        report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.review_required)
            .map(|gap| gap_diagnostic(gap, run_dir)),
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, rule_id: &str, severity: &str, title: &str, file: &str, line: i64) -> FindingInput {
        FindingInput {
            id: Some(id.to_string()),
            rule_id: Some(rule_id.to_string()),
            severity: Some(severity.to_string()),
            title: Some(title.to_string()),
            file: Some(file.to_string()),
            line: Some(line),
            ..Default::default()
        }
    }

    #[test]
    fn diagnostics_map_findings_to_stable_diagnostics() {
        let input = EditorInput {
            run_dir: Some("/run".to_string()),
            report: Some(ReportInput {
                findings: vec![
                    finding("f1", "r1", "critical", "Credential", "a.ts", 3),
                    finding("f2", "r2", "medium", "Warning", "b.ts", 9),
                ],
                coverage_gaps: vec![],
            }),
        };
        let diagnostics = editor_diagnostics(&input);
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0]["kind"], "legion-editor-diagnostic");
        assert_eq!(diagnostics[0]["severity"], 1);
        assert_eq!(diagnostics[1]["severity"], 2);
        assert_eq!(diagnostics[0]["file"], "a.ts");
        let actions = diagnostics[0]["codeActions"].as_array().unwrap();
        assert!(actions.iter().any(|a| a["kind"] == "explain"));
    }

    #[test]
    fn diagnostics_carry_stable_fingerprints_never_line_bound_identity() {
        let mut f1 = finding("f1", "r", "info", "T", "a.ts", 3);
        f1.fingerprint = Some("sha256:fp".to_string());
        let a = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f1], coverage_gaps: vec![] }),
        });
        let mut f1b = finding("f1", "r", "info", "T", "a.ts", 99);
        f1b.fingerprint = Some("sha256:fp".to_string());
        let b = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f1b], coverage_gaps: vec![] }),
        });
        assert_eq!(a[0]["fingerprint"], b[0]["fingerprint"]);
        assert_ne!(a[0]["line"], b[0]["line"]);
    }

    #[test]
    fn diagnostics_never_create_a_second_rule_engine() {
        let f = FindingInput {
            id: Some("f1".to_string()),
            rule_id: Some("credentials.format".to_string()),
            file: Some("a.ts".to_string()),
            line: Some(1),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        assert_eq!(diagnostics[0]["code"], "credentials.format");
    }

    #[test]
    fn missing_report_yields_no_diagnostics() {
        let diagnostics = editor_diagnostics(&EditorInput { report: None, run_dir: None });
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn coverage_gap_requires_review_required_true() {
        let report = ReportInput {
            findings: vec![],
            coverage_gaps: vec![
                CoverageGapInput {
                    review_required: true,
                    id: Some("g1".to_string()),
                    kind: Some("missing-provider".to_string()),
                    detail: None,
                    family: Some("architecture".to_string()),
                },
                CoverageGapInput {
                    review_required: false,
                    id: Some("g2".to_string()),
                    ..Default::default()
                },
            ],
        };
        let diagnostics = editor_diagnostics(&EditorInput { report: Some(report), run_dir: Some("/run".to_string()) });
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0]["fingerprint"], "g1");
        assert_eq!(diagnostics[0]["message"], "missing-provider");
        assert_eq!(diagnostics[0]["coverageIncomplete"], true);
        assert_eq!(diagnostics[0]["family"], "architecture");
    }

    #[test]
    fn gap_without_id_falls_back_to_gap_prefixed_kind() {
        let report = ReportInput {
            findings: vec![],
            coverage_gaps: vec![CoverageGapInput {
                review_required: true,
                id: None,
                kind: Some("stale".to_string()),
                detail: None,
                family: None,
            }],
        };
        let diagnostics = editor_diagnostics(&EditorInput { report: Some(report), run_dir: None });
        assert_eq!(diagnostics[0]["fingerprint"], "gap:stale");
    }

    #[test]
    fn qualified_remediation_adds_preview_action() {
        let f = FindingInput {
            id: Some("f1".to_string()),
            rule_id: Some("r1".to_string()),
            fingerprint: Some("sha256:abcd".to_string()),
            remediation: Some(Remediation {
                id: Some("proposal-1".to_string()),
                qualified: Some(true),
                patch: Some(RemediationPatch {
                    digest: Some(format!("sha256:{}", "a".repeat(64))),
                    extra: serde_json::Map::new(),
                }),
                finding_fingerprint: Some("sha256:abcd".to_string()),
                finding_ids: Some(vec!["f1".to_string()]),
            }),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        let actions = diagnostics[0]["codeActions"].as_array().unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0]["kind"], "preview");
        assert_eq!(actions[0]["proposalId"], "proposal-1");
        assert_eq!(actions[1]["kind"], "explain");
    }

    #[test]
    fn unqualified_remediation_omits_preview_action() {
        let f = FindingInput {
            id: Some("f1".to_string()),
            rule_id: Some("r1".to_string()),
            remediation: Some(Remediation {
                qualified: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        let actions = diagnostics[0]["codeActions"].as_array().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "explain");
    }

    #[test]
    fn bad_digest_format_omits_preview_action() {
        let f = FindingInput {
            id: Some("f1".to_string()),
            remediation: Some(Remediation {
                qualified: Some(true),
                patch: Some(RemediationPatch {
                    digest: Some("not-a-digest".to_string()),
                    extra: serde_json::Map::new(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        let actions = diagnostics[0]["codeActions"].as_array().unwrap();
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn finding_ids_mismatch_omits_preview_action() {
        let f = FindingInput {
            id: Some("f1".to_string()),
            remediation: Some(Remediation {
                qualified: Some(true),
                patch: Some(RemediationPatch {
                    digest: Some(format!("sha256:{}", "b".repeat(64))),
                    extra: serde_json::Map::new(),
                }),
                finding_ids: Some(vec!["other-finding".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        let actions = diagnostics[0]["codeActions"].as_array().unwrap();
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn no_id_and_no_rule_id_yields_no_code_actions() {
        let f = FindingInput {
            severity: Some("low".to_string()),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        let actions = diagnostics[0]["codeActions"].as_array().unwrap();
        assert!(actions.is_empty());
        // Unknown severity falls through to info (3).
        assert_eq!(diagnostics[0]["severity"], 3);
    }

    #[test]
    fn explicit_range_is_passed_through_verbatim() {
        let f = FindingInput {
            id: Some("f1".to_string()),
            range: Some(json!({"start": {"line": 5, "column": 2}, "end": {"line": 5, "column": 9}, "extra": "kept"})),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        assert_eq!(diagnostics[0]["range"]["extra"], "kept");
        assert_eq!(diagnostics[0]["line"], 5);
        assert_eq!(diagnostics[0]["column"], 2);
    }

    #[test]
    fn stale_content_id_sets_lineage_state() {
        let f = FindingInput {
            id: Some("f1".to_string()),
            stale_content_id: Some("prior-1".to_string()),
            content_id: Some("current-1".to_string()),
            ..Default::default()
        };
        let diagnostics = editor_diagnostics(&EditorInput {
            run_dir: None,
            report: Some(ReportInput { findings: vec![f], coverage_gaps: vec![] }),
        });
        assert_eq!(diagnostics[0]["lineage"]["state"], "stale");
        assert_eq!(diagnostics[0]["lineage"]["priorContentId"], "prior-1");
    }
}
