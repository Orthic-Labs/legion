use legion_contracts::ReportV1;

use crate::{
    error::{validate, ReportError},
    escape, ordered_findings,
};

pub fn render(report: &ReportV1) -> Result<String, ReportError> {
    validate(report)?;
    let mut output = String::from("# Legion Report\n\n");
    output.push_str("- Status: ");
    output.push_str(&escape::markdown_code(crate::status_label(report.status)));
    output.push_str("\n- Report ID: ");
    output.push_str(&escape::markdown_code(report.report_id.as_str()));
    output.push_str("\n\n## Targets\n\n");
    if report.targets.is_empty() {
        output.push_str("No targets recorded.\n\n");
    } else {
        for target in &report.targets {
            output.push_str("- ");
            output.push_str(&escape::markdown_code(target));
            output.push('\n');
        }
        output.push('\n');
    }
    output.push_str("## Claims\n\n");
    if report.claims.is_empty() {
        output.push_str("No claims recorded.\n\n");
    } else {
        for (key, value) in &report.claims {
            output.push_str("- ");
            output.push_str(&escape::markdown_code(key));
            output.push_str(": ");
            output.push_str(&escape::markdown_code(&value.to_string()));
            output.push('\n');
        }
        output.push('\n');
    }
    output.push_str("## Coverage & omissions\n\n");
    if report.gaps.is_empty() {
        output.push_str("No omissions recorded.\n\n");
    } else {
        for gap in &report.gaps {
            output.push_str("- ");
            output.push_str(&escape::markdown(gap));
            output.push('\n');
        }
        output.push('\n');
    }
    output.push_str(&crate::assurance_view::markdown(
        &crate::assurance_view::view(&report.extensions),
        true,
    ));
    output.push_str("## Findings\n\n");
    let findings = ordered_findings(report);
    if findings.is_empty() {
        output.push_str("No findings recorded; status remains authoritative.\n\n");
    }
    for finding in findings {
        output.push_str("### ");
        output.push_str(&escape::markdown(finding.id.as_str()));
        output.push_str(" — ");
        output.push_str(&escape::markdown(&finding.title));
        output.push_str("\n\n- Severity: ");
        output.push_str(&escape::markdown_code(&finding.severity));
        output.push_str("\n- Message: ");
        output.push_str(&escape::markdown(&finding.message));
        output.push('\n');
        if let Some(provider) = &finding.provider {
            output.push_str("- Provider: ");
            output.push_str(&escape::markdown(provider));
            output.push('\n');
        }
        if !finding.locations.is_empty() {
            output.push_str("- Locations: ");
            output.push_str(
                &finding
                    .locations
                    .iter()
                    .map(|location| escape::markdown_code(location))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            output.push('\n');
        }
        if !finding.evidence.is_empty() {
            output.push_str("- Evidence:\n");
            for (key, value) in &finding.evidence {
                output.push_str("  - ");
                output.push_str(&escape::markdown_code(key));
                output.push_str(": ");
                output.push_str(&escape::markdown_code(&value.to_string()));
                output.push('\n');
            }
        }
        output.push('\n');
    }
    Ok(output)
}

pub fn to_markdown(report: &ReportV1) -> Result<String, ReportError> {
    render(report)
}

#[cfg(test)]
mod assurance_tests {
    use std::collections::BTreeMap;

    use legion_contracts::{ReportId, ReportStatus, ReportV1};
    use serde_json::{json, Value};

    fn report(extension: Option<Value>) -> ReportV1 {
        let mut extensions = BTreeMap::new();
        if let Some(value) = extension {
            extensions.insert("auditAssuranceV1".to_owned(), value);
        }
        ReportV1 {
            schema_version: 1,
            report_id: ReportId::new("report:assurance").unwrap(),
            status: ReportStatus::Incomplete,
            findings: Vec::new(),
            gaps: vec!["assurance-unmet:t:source".into()],
            claims: BTreeMap::new(),
            targets: vec!["fixture".into()],
            extensions,
        }
    }

    fn ext(
        profile: &str,
        completion: &str,
        outcome: &str,
        eligibility: &str,
        status: &str,
    ) -> Value {
        json!({
            "schemaVersion": 1,
            "profile": {"profile": profile},
            "runtimeConstraint": "no-node-python",
            "productTarget": {"product": "p", "target": "t"},
            "obligations": [{
                "id": {"concern": "source", "target": "t", "evidenceKind": "provider-execution"},
                "status": status,
                "reason": "not-examined",
                "waiver": if status == "waived" {
                    json!({"grantedBy": "owner:a", "rationale": "debt", "expiresAt": "2027-01-01T00:00:00Z"})
                } else { Value::Null }
            }],
            "summary": {
                "completion": completion, "findingOutcome": outcome,
                "releaseEligibility": eligibility,
                "total": 1, "satisfied": 0, "findings": 0, "unmet": 1,
                "deferred": 0, "waived": 0, "inapplicable": 0
            }
        })
    }

    #[test]
    fn legacy_report_says_not_recorded_and_not_assessed() {
        let md = crate::markdown::render(&report(None)).unwrap();
        assert!(md.contains("## Assurance"));
        assert!(md.contains("Not recorded"));
        assert!(md.contains("cannot carry release eligibility"));
        let html = crate::html::render(&report(None)).unwrap();
        assert!(html.contains("<h2>Assurance</h2>"));
    }

    #[test]
    fn three_axes_and_uncertainty_render_distinctly() {
        let md = crate::markdown::render(&report(Some(ext(
            "pre-pr",
            "partial",
            "unproven",
            "not-assessed",
            "unmet",
        ))))
        .unwrap();
        assert!(md.contains("- Completion: `partial`"));
        assert!(md.contains("- Finding outcome: `unproven`"));
        assert!(md.contains("- Release eligibility: not-assessed"));
        assert!(md.contains("### Inherited uncertainty"));
        assert!(md.contains("does not project to release"));
        assert!(md.contains("### Waivers and debt"));
    }

    #[test]
    fn waiver_is_shown_as_not_executed() {
        let md = crate::markdown::render(&report(Some(ext(
            "release",
            "partial",
            "unproven",
            "not-eligible",
            "waived",
        ))))
        .unwrap();
        assert!(md.contains("not executed"));
        assert!(md.contains("owner:a"));
    }

    #[test]
    fn unsupported_inconsistent_or_malformed_extension_never_shows_eligible() {
        let future = json!({"schemaVersion": 2});
        let md = crate::markdown::render(&report(Some(future))).unwrap();
        assert!(md.contains("malformed or unsupported"));
        assert!(!md.contains("Release eligibility: eligible"));
        let forged = ext("release", "complete", "clean", "eligible", "unmet");
        let md = crate::markdown::render(&report(Some(forged))).unwrap();
        assert!(!md.contains("Release eligibility: eligible"));
        assert!(md.contains("not-eligible"));
        let weak = ext("pre-pr", "complete", "clean", "eligible", "satisfied");
        let md = crate::markdown::render(&report(Some(weak))).unwrap();
        assert!(!md.contains("Release eligibility: eligible"));
    }

    #[test]
    fn sarif_and_json_carry_assurance() {
        let r = report(Some(ext(
            "release",
            "partial",
            "unproven",
            "not-eligible",
            "unmet",
        )));
        let sarif: Value = serde_json::from_str(&crate::sarif::render(&r).unwrap()).unwrap();
        let a = &sarif["runs"][0]["properties"]["assurance"];
        assert_eq!(a["recorded"], json!(true));
        assert_eq!(a["completion"], json!("partial"));
        let legacy: Value =
            serde_json::from_str(&crate::sarif::render(&report(None)).unwrap()).unwrap();
        assert_eq!(
            legacy["runs"][0]["properties"]["assurance"]["releaseEligibility"],
            json!("not-assessed")
        );
        let json_out: Value = serde_json::from_str(&crate::json::render(&r).unwrap()).unwrap();
        assert_eq!(
            json_out["auditAssuranceV1"]["summary"]["completion"],
            json!("partial")
        );
    }
}
