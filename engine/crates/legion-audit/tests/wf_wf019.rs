//! Integration tests porting the JS test coverage for
//! `src/lib/report/editor/index.mjs` (see `../../../../tests/report/editor.test.mjs`
//! in the JS tree) and for `buildFamilySummary` from
//! `src/lib/report/families/shared.mjs`, re-exported verbatim by
//! `architecture.mjs`/`code.mjs`/`compatibility.mjs`/`data-integrity.mjs`.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf019;`
//! inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf019::{
    build_family_summary, editor_diagnostics, Denominator, EditorInput, FamilyResult,
};
use legion_audit::wf_port::wf019::editor_diagnostics::{CoverageGapInput, FindingInput, ReportInput};

#[test]
fn editor_diagnostics_map_findings_to_stable_diagnostics() {
    let report = ReportInput {
        findings: vec![
            FindingInput {
                id: Some("f1".to_string()),
                rule_id: Some("r1".to_string()),
                severity: Some("critical".to_string()),
                title: Some("Credential".to_string()),
                file: Some("a.ts".to_string()),
                line: Some(3),
                ..Default::default()
            },
            FindingInput {
                id: Some("f2".to_string()),
                rule_id: Some("r2".to_string()),
                severity: Some("medium".to_string()),
                title: Some("Warning".to_string()),
                file: Some("b.ts".to_string()),
                line: Some(9),
                ..Default::default()
            },
        ],
        coverage_gaps: vec![],
    };
    let diagnostics = editor_diagnostics(&EditorInput {
        report: Some(report),
        run_dir: Some("/run".to_string()),
    });
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
    let a = editor_diagnostics(&EditorInput {
        report: Some(ReportInput {
            findings: vec![FindingInput {
                id: Some("f1".to_string()),
                rule_id: Some("r".to_string()),
                file: Some("a.ts".to_string()),
                line: Some(3),
                fingerprint: Some("sha256:fp".to_string()),
                ..Default::default()
            }],
            coverage_gaps: vec![],
        }),
        run_dir: None,
    });
    let b = editor_diagnostics(&EditorInput {
        report: Some(ReportInput {
            findings: vec![FindingInput {
                id: Some("f1".to_string()),
                rule_id: Some("r".to_string()),
                file: Some("a.ts".to_string()),
                line: Some(99),
                fingerprint: Some("sha256:fp".to_string()),
                ..Default::default()
            }],
            coverage_gaps: vec![],
        }),
        run_dir: None,
    });
    assert_eq!(a[0]["fingerprint"], b[0]["fingerprint"]);
    assert_ne!(a[0]["line"], b[0]["line"]);
}

#[test]
fn diagnostics_never_create_a_second_rule_engine() {
    let diagnostics = editor_diagnostics(&EditorInput {
        report: Some(ReportInput {
            findings: vec![FindingInput {
                id: Some("f1".to_string()),
                rule_id: Some("credentials.format".to_string()),
                file: Some("a.ts".to_string()),
                line: Some(1),
                ..Default::default()
            }],
            coverage_gaps: vec![],
        }),
        run_dir: None,
    });
    assert_eq!(diagnostics[0]["code"], "credentials.format");
}

#[test]
fn coverage_gap_diagnostics_require_review_required() {
    let diagnostics = editor_diagnostics(&EditorInput {
        report: Some(ReportInput {
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
        }),
        run_dir: Some("/run".to_string()),
    });
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["fingerprint"], "g1");
    assert_eq!(diagnostics[0]["coverageIncomplete"], true);
}

#[test]
fn family_summary_clean_for_complete_results() {
    let results = vec![FamilyResult {
        id: Some("providerA".to_string()),
        provider: None,
        family: Some("architecture".to_string()),
        complete: Some(true),
        status: Some("pass".to_string()),
        denominator: Some(Denominator { expected: 5.0, examined: 5.0 }),
        tool: None,
        raw_artifacts: vec![],
        component_ids: vec![],
        limitations: vec![],
    }];
    let summary = build_family_summary(&results, Some("architecture"), &["providerA".to_string()], &[]);
    assert!(summary.clean);
    assert_eq!(summary.status, "complete");
    assert!(summary.gaps.is_empty());
}

#[test]
fn family_summary_reports_missing_and_incomplete_providers() {
    let results = vec![FamilyResult {
        id: Some("providerA".to_string()),
        provider: None,
        family: Some("code".to_string()),
        complete: Some(true),
        status: Some("pass".to_string()),
        denominator: Some(Denominator { expected: 2.0, examined: 1.0 }),
        tool: None,
        raw_artifacts: vec![],
        component_ids: vec![],
        limitations: vec![],
    }];
    let summary = build_family_summary(
        &results,
        Some("code"),
        &["providerA".to_string(), "providerB".to_string()],
        &[],
    );
    assert!(!summary.clean);
    assert_eq!(summary.status, "incomplete");
    let kinds: Vec<&str> = summary.gaps.iter().map(|g| g.kind.as_str()).collect();
    assert!(kinds.contains(&"required-provider-missing"));
    assert!(kinds.contains(&"provider-result-incomplete"));
    assert_eq!(
        summary.incomplete_providers,
        vec!["providerA".to_string(), "providerB".to_string()]
    );
}
