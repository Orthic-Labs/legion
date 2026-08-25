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
