use legion_contracts::ReportV1;

use crate::{
    error::{validate, ReportError},
    escape, ordered_findings,
};

pub fn render(report: &ReportV1) -> Result<String, ReportError> {
    validate(report)?;
    let mut output = String::from("<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>Legion Report</title></head>\n<body>\n<h1>Legion Report</h1>\n");
    output.push_str("<p>Status: <code>");
    output.push_str(&escape::html(
        &format!("{:?}", report.status).to_ascii_lowercase(),
    ));
    output.push_str("</code></p>\n");
    output.push_str("<h2>Coverage &amp; omissions</h2>\n<ul>\n");
    if report.gaps.is_empty() {
        output.push_str("<li>No omissions recorded.</li>\n");
    }
    for gap in &report.gaps {
        output.push_str("<li>");
        output.push_str(&escape::html(gap));
        output.push_str("</li>\n");
    }
    output.push_str("</ul>\n<h2>Findings</h2>\n");
    if report.findings.is_empty() {
        output.push_str("<p>No findings recorded; status remains authoritative.</p>\n");
    }
    for finding in ordered_findings(report) {
        output.push_str("<article><h3><code>");
        output.push_str(&escape::html(finding.id.as_str()));
        output.push_str("</code> — ");
        output.push_str(&escape::html(&finding.title));
        output.push_str("</h3>\n");
        output.push_str("<p><strong>Severity:</strong> <code>");
        output.push_str(&escape::html(&finding.severity));
        output.push_str("</code><br><strong>Message:</strong> ");
        output.push_str(&escape::html(&finding.message));
        output.push_str("</p>\n");
        if !finding.locations.is_empty() {
            output.push_str("<p><strong>Locations:</strong> ");
            output.push_str(
                &finding
                    .locations
                    .iter()
                    .map(|location| format!("<code>{}</code>", escape::html(location)))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            output.push_str("</p>\n");
        }
        if !finding.evidence.is_empty() {
            output.push_str("<h4>Evidence</h4><ul>\n");
            for (key, value) in &finding.evidence {
                output.push_str("<li><code>");
                output.push_str(&escape::html(key));
                output.push_str("</code>: ");
                output.push_str(&escape::html(&value.to_string()));
                output.push_str("</li>\n");
            }
            output.push_str("</ul>\n");
        }
        output.push_str("</article>\n");
    }
    output.push_str("</body>\n</html>\n");
    Ok(output)
}

pub fn to_html(report: &ReportV1) -> Result<String, ReportError> {
    render(report)
}
