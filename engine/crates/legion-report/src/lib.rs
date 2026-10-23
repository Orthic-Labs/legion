#![forbid(unsafe_code)]

use legion_contracts::{Finding, ReportStatus, ReportV1, ReportV2};

pub mod error;
pub mod escape;
pub mod html;
pub mod json;
pub mod markdown;
pub mod ponytail;
pub mod review;
pub mod sarif;
pub mod trend;

pub use error::ReportError;

pub fn render_json(report: &ReportV1) -> Result<String, ReportError> {
    json::render(report)
}
/// Renders a v2 report as schema 2 (native) or schema 1 (projection).
pub fn render_json_schema(report: &ReportV2, schema: u32) -> Result<String, ReportError> {
    json::render_schema(report, schema)
}
pub fn render_sarif(report: &ReportV1) -> Result<String, ReportError> {
    sarif::render(report)
}
pub fn render_markdown(report: &ReportV1) -> Result<String, ReportError> {
    markdown::render(report)
}
pub fn render_html(report: &ReportV1) -> Result<String, ReportError> {
    html::render(report)
}

/// Renders an evidence-preserving source review from a schema-v2 report.
pub fn render_review(report: &ReportV2) -> Result<String, ReportError> {
    report
        .validate()
        .map_err(|error| ReportError::Contract(error.to_string()))?;
    Ok(review::render(report))
}

/// Renders the canonical Ponytail five-tag finding projection from a v2 report.
pub fn render_ponytail(report: &ReportV2) -> Result<String, ReportError> {
    report
        .validate()
        .map_err(|error| ReportError::Contract(error.to_string()))?;
    Ok(ponytail::render(report))
}

/// Renders GitHub's review-file JSON shape. This only creates a local payload;
/// it never posts a review or comment.
pub fn render_github_review(report: &ReportV2) -> Result<String, ReportError> {
    report
        .validate()
        .map_err(|error| ReportError::Contract(error.to_string()))?;
    review::render_github_review(report)
}

/// JSON-only view of the `auditAssuranceV1` report extension. legion-report
/// never links Audit types: it reads the versioned extension as data, shows
/// completion, finding outcome and release eligibility as three independent
/// facts, and never upgrades a malformed, future-versioned or inconsistent
/// extension into an eligibility claim.
pub(crate) mod assurance_view {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use crate::escape;

    pub(crate) const KEY: &str = legion_contracts::report::AUDIT_ASSURANCE_EXTENSION_KEY;

    pub(crate) struct Row {
        pub concern: String,
        pub target: String,
        pub kind: String,
        pub status: String,
        pub reason: String,
        /// (granted_by, rationale, expires_at)
        pub waiver: Option<(String, String, String)>,
    }

    pub(crate) struct Facts {
        pub profile: String,
        pub runtime_constraint: String,
        pub product: String,
        pub target: String,
        pub completion: String,
        pub finding_outcome: String,
        pub release_eligibility: String,
        pub counts: Vec<(String, u64)>,
        pub rows: Vec<Row>,
    }

    pub(crate) enum View {
        Absent,
        Invalid(String),
        Present(Facts),
    }

    fn text(value: &Value, key: &str) -> Option<String> {
        value.get(key).and_then(Value::as_str).map(str::to_owned)
    }

    pub(crate) fn view(extensions: &BTreeMap<String, Value>) -> View {
        let Some(value) = extensions.get(KEY) else {
            return View::Absent;
        };
        match parse(value) {
            Ok(facts) => View::Present(facts),
            Err(reason) => View::Invalid(reason),
        }
    }

    fn parse(value: &Value) -> Result<Facts, String> {
        match value.get("schemaVersion").and_then(Value::as_u64) {
            Some(1) => {}
            Some(other) => return Err(format!("unsupported schemaVersion {other}")),
            None => return Err("missing schemaVersion".into()),
        }
        let summary = value.get("summary").ok_or("missing summary")?;
        let need = |v: &Value, k: &str| text(v, k).ok_or_else(|| format!("missing {k}"));
        let profile = value
            .get("profile")
            .and_then(|p| text(p, "profile"))
            .ok_or("missing profile")?;
        let product_target = value.get("productTarget").ok_or("missing productTarget")?;
        let mut counts = Vec::new();
        for key in [
            "total",
            "satisfied",
            "findings",
            "unmet",
            "deferred",
            "waived",
            "inapplicable",
        ] {
            let n = summary
                .get(key)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("missing summary.{key}"))?;
            counts.push((key.to_owned(), n));
        }
        let mut rows = Vec::new();
        for item in value
            .get("obligations")
            .and_then(Value::as_array)
            .ok_or("missing obligations")?
        {
            let id = item.get("id").ok_or("obligation missing id")?;
            rows.push(Row {
                concern: need(id, "concern")?,
                target: need(id, "target")?,
                kind: need(id, "evidenceKind")?,
                status: need(item, "status")?,
                reason: text(item, "reason").unwrap_or_default(),
                waiver: item.get("waiver").filter(|w| w.is_object()).map(|w| {
                    (
                        text(w, "grantedBy").unwrap_or_default(),
                        text(w, "rationale").unwrap_or_default(),
                        text(w, "expiresAt").unwrap_or_default(),
                    )
                }),
            });
        }
        let completion = need(summary, "completion")?;
        let finding_outcome = need(summary, "findingOutcome")?;
        let claimed = need(summary, "releaseEligibility")?;
        let open = rows
            .iter()
            .any(|r| matches!(r.status.as_str(), "unmet" | "deferred" | "waived"));
        let has_findings = rows.iter().any(|r| r.status == "findings");
        // Display-time guard: an eligibility claim is shown only when the
        // rows themselves support it.
        let release_eligibility = if claimed == "eligible"
            && !(profile == "release"
                && completion == "complete"
                && finding_outcome == "clean"
                && !open
                && !has_findings)
        {
            "not-eligible (extension claims eligible but its obligations do not support it)"
                .to_owned()
        } else {
            claimed
        };
        Ok(Facts {
            profile,
            runtime_constraint: text(value, "runtimeConstraint").unwrap_or_default(),
            product: need(product_target, "product")?,
            target: need(product_target, "target")?,
            completion,
            finding_outcome,
            release_eligibility,
            counts,
            rows,
        })
    }

    impl Facts {
        pub(crate) fn uncertain(&self) -> Vec<&Row> {
            self.rows
                .iter()
                .filter(|r| matches!(r.status.as_str(), "unmet" | "deferred"))
                .collect()
        }
        pub(crate) fn waived(&self) -> Vec<&Row> {
            self.rows.iter().filter(|r| r.status == "waived").collect()
        }
        pub(crate) fn examined(&self) -> Vec<&Row> {
            self.rows
                .iter()
                .filter(|r| matches!(r.status.as_str(), "satisfied" | "findings"))
                .collect()
        }
        pub(crate) fn weaker_than_release(&self) -> bool {
            self.profile != "release"
        }
    }

    fn row_line(row: &Row) -> String {
        let mut line = format!(
            "{} / {} / {} [{}]",
            escape::markdown_code(&row.target),
            escape::markdown_code(&row.concern),
            escape::markdown_code(&row.kind),
            escape::markdown_code(&row.status),
        );
        if !row.reason.is_empty() {
            line.push_str(": ");
            line.push_str(&escape::markdown(&row.reason));
        }
        line
    }

    /// Markdown `## Assurance` section (also embedded by Ponytail).
    pub(crate) fn markdown(view: &View, always: bool) -> String {
        let mut out = String::new();
        match view {
            View::Absent => {
                if always {
                    out.push_str("## Assurance\n\nNot recorded (legacy report without `auditAssuranceV1`). Completion, finding outcome and release eligibility were not assessed; this report cannot carry release eligibility.\n\n");
                }
            }
            View::Invalid(reason) => {
                out.push_str("## Assurance\n\n");
                out.push_str(&format!(
                    "Extension `{KEY}` is malformed or unsupported ({}). It is not interpreted; release eligibility: not assessed.\n\n",
                    escape::markdown(reason)
                ));
            }
            View::Present(f) => {
                out.push_str("## Assurance\n\n");
                out.push_str(&format!(
                    "- Profile: {}; runtime constraint: {}\n- Product target: {} / {}\n- Completion: {}\n- Finding outcome: {}\n- Release eligibility: {}\n- Counts: {}\n\n",
                    escape::markdown_code(&f.profile),
                    escape::markdown_code(&f.runtime_constraint),
                    escape::markdown_code(&f.product),
                    escape::markdown_code(&f.target),
                    escape::markdown_code(&f.completion),
                    escape::markdown_code(&f.finding_outcome),
                    escape::markdown(&f.release_eligibility),
                    f.counts
                        .iter()
                        .map(|(k, n)| format!("{k}={n}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
                if f.finding_outcome == "findings" {
                    out.push_str(
                        "Obligations were satisfied with findings: this is not a clean result.\n\n",
                    );
                }
                out.push_str("### Examined obligations\n\n");
                let examined = f.examined();
                if examined.is_empty() {
                    out.push_str("None examined.\n\n");
                }
                for row in examined {
                    out.push_str(&format!("- {}\n", row_line(row)));
                }
                out.push('\n');
                out.push_str("### Inherited uncertainty\n\n");
                let uncertain = f.uncertain();
                if uncertain.is_empty() && !f.weaker_than_release() {
                    out.push_str("None recorded.\n\n");
                }
                for row in uncertain {
                    out.push_str(&format!("- {}\n", row_line(row)));
                }
                if f.weaker_than_release() {
                    out.push_str(&format!(
                        "- Profile {} does not project to release: release-only obligations were not part of this run.\n",
                        escape::markdown_code(&f.profile)
                    ));
                }
                out.push('\n');
                out.push_str("### Waivers and debt\n\n");
                let waived = f.waived();
                if waived.is_empty() {
                    out.push_str(
                        "No waivers. Waived obligations are never counted as executed.\n\n",
                    );
                }
                for row in waived {
                    out.push_str(&format!("- {}", row_line(row)));
                    if let Some((by, why, until)) = &row.waiver {
                        out.push_str(&format!(
                            " (waived by {}, expires {}: {}; not executed)",
                            escape::markdown_code(by),
                            escape::markdown_code(until),
                            escape::markdown(why)
                        ));
                    }
                    out.push('\n');
                }
                if !f.waived().is_empty() {
                    out.push('\n');
                }
            }
        }
        out
    }

    /// HTML `<h2>Assurance</h2>` section.
    pub(crate) fn html(view: &View) -> String {
        let h = escape::html;
        let li = |row: &Row| {
            let mut s = format!(
                "<li><code>{}</code> / <code>{}</code> / <code>{}</code> [<code>{}</code>]",
                h(&row.target),
                h(&row.concern),
                h(&row.kind),
                h(&row.status)
            );
            if !row.reason.is_empty() {
                s.push_str(": ");
                s.push_str(&h(&row.reason));
            }
            if let Some((by, why, until)) = &row.waiver {
                s.push_str(&format!(
                    " (waived by <code>{}</code>, expires <code>{}</code>: {}; not executed)",
                    h(by),
                    h(until),
                    h(why)
                ));
            }
            s.push_str("</li>\n");
            s
        };
        match view {
            View::Absent => "<h2>Assurance</h2>\n<p>Not recorded (legacy report without <code>auditAssuranceV1</code>). Release eligibility: not assessed; this report cannot carry release eligibility.</p>\n".to_owned(),
            View::Invalid(reason) => format!(
                "<h2>Assurance</h2>\n<p>Extension <code>{KEY}</code> is malformed or unsupported ({}). It is not interpreted; release eligibility: not assessed.</p>\n",
                h(reason)
            ),
            View::Present(f) => {
                let mut out = format!(
                    "<h2>Assurance</h2>\n<ul>\n<li>Profile: <code>{}</code>; runtime constraint: <code>{}</code></li>\n<li>Product target: <code>{}</code> / <code>{}</code></li>\n<li>Completion: <code>{}</code></li>\n<li>Finding outcome: <code>{}</code></li>\n<li>Release eligibility: {}</li>\n<li>Counts: {}</li>\n</ul>\n",
                    h(&f.profile),
                    h(&f.runtime_constraint),
                    h(&f.product),
                    h(&f.target),
                    h(&f.completion),
                    h(&f.finding_outcome),
                    h(&f.release_eligibility),
                    h(&f.counts.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>().join(", ")),
                );
                if f.finding_outcome == "findings" {
                    out.push_str("<p>Obligations were satisfied with findings: this is not a clean result.</p>\n");
                }
                out.push_str("<h3>Examined obligations</h3>\n<ul>\n");
                let examined = f.examined();
                if examined.is_empty() {
                    out.push_str("<li>None examined.</li>\n");
                }
                for row in examined {
                    out.push_str(&li(row));
                }
                out.push_str("</ul>\n<h3>Inherited uncertainty</h3>\n<ul>\n");
                let uncertain = f.uncertain();
                if uncertain.is_empty() && !f.weaker_than_release() {
                    out.push_str("<li>None recorded.</li>\n");
                }
                for row in uncertain {
                    out.push_str(&li(row));
                }
                if f.weaker_than_release() {
                    out.push_str(&format!(
                        "<li>Profile <code>{}</code> does not project to release: release-only obligations were not part of this run.</li>\n",
                        h(&f.profile)
                    ));
                }
                out.push_str("</ul>\n<h3>Waivers and debt</h3>\n<ul>\n");
                let waived = f.waived();
                if waived.is_empty() {
                    out.push_str("<li>No waivers. Waived obligations are never counted as executed.</li>\n");
                }
                for row in waived {
                    out.push_str(&li(row));
                }
                out.push_str("</ul>\n");
                out
            }
        }
    }

    /// SARIF `run.properties.assurance` value.
    pub(crate) fn sarif(view: &View) -> Value {
        use serde_json::json;
        match view {
            View::Absent => json!({
                "recorded": false,
                "releaseEligibility": "not-assessed",
                "note": "legacy report without auditAssuranceV1; cannot carry release eligibility"
            }),
            View::Invalid(reason) => json!({
                "recorded": false,
                "invalid": reason,
                "releaseEligibility": "not-assessed"
            }),
            View::Present(f) => {
                let rows = |rows: Vec<&Row>| {
                    rows.into_iter()
                        .map(|r| json!({"target": r.target, "concern": r.concern, "evidenceKind": r.kind, "status": r.status, "reason": r.reason}))
                        .collect::<Vec<_>>()
                };
                json!({
                    "recorded": true,
                    "profile": f.profile,
                    "runtimeConstraint": f.runtime_constraint,
                    "completion": f.completion,
                    "findingOutcome": f.finding_outcome,
                    "releaseEligibility": f.release_eligibility,
                    "counts": f.counts.iter().cloned().collect::<BTreeMap<_, _>>(),
                    "inheritedUncertainty": rows(f.uncertain()),
                    "waived": f.waived().into_iter().map(|r| json!({
                        "target": r.target, "concern": r.concern, "evidenceKind": r.kind,
                        "grantedBy": r.waiver.as_ref().map(|w| w.0.clone()),
                        "expiresAt": r.waiver.as_ref().map(|w| w.2.clone()),
                        "executed": false
                    })).collect::<Vec<_>>()
                })
            }
        }
    }
}

pub(crate) fn status_label(status: ReportStatus) -> &'static str {
    match status {
        ReportStatus::Clean => "clean",
        ReportStatus::Findings => "findings",
        ReportStatus::Incomplete => "incomplete",
        ReportStatus::Failed => "failed",
        ReportStatus::Blocked => "blocked",
    }
}

pub(crate) fn ordered_findings(report: &ReportV1) -> Vec<&Finding> {
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by(|left, right| {
        left.id
            .as_str()
            .cmp(right.id.as_str())
            .then_with(|| first_location(left).cmp(&first_location(right)))
            .then_with(|| left.message.cmp(&right.message))
    });
    findings
}

fn first_location(finding: &Finding) -> (String, u64, u64) {
    finding
        .locations
        .iter()
        .map(|location| {
            let normalized = location.replace('\\', "/");
            let (path, span) = normalized
                .rsplit_once(':')
                .unwrap_or((normalized.as_str(), ""));
            let (start, end) = span.split_once('-').unwrap_or((span, span));
            let start = start.parse::<u64>().unwrap_or(0);
            let end = end.parse::<u64>().unwrap_or(start);
            (path.to_string(), start, end)
        })
        .min()
        .unwrap_or_else(|| (String::new(), 0, 0))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use legion_contracts::{FindingId, ReportId};
    use serde_json::json;

    use super::*;

    fn report(status: ReportStatus, findings: Vec<Finding>) -> ReportV1 {
        ReportV1 {
            schema_version: 1,
            report_id: ReportId::new("report-1").unwrap(),
            status,
            findings,
            gaps: vec!["provider denominator unavailable".into()],
            claims: BTreeMap::from([("coverage".into(), json!({"examined": 0}))]),
            targets: vec!["src/lib.rs".into()],
            extensions: BTreeMap::new(),
        }
    }

    fn finding(id: &str, title: &str) -> Finding {
        Finding {
            id: FindingId::new(id).unwrap(),
            severity: "high".into(),
            title: title.into(),
            message: "message".into(),
            provider: Some("rules".into()),
            locations: vec!["src/lib.rs:12-14".into()],
            evidence: BTreeMap::from([("source".into(), json!("fixture"))]),
        }
    }

    #[test]
    fn rejects_invalid_contract_before_rendering() {
        let mut invalid = report(ReportStatus::Clean, Vec::new());
        invalid.schema_version = 2;
        for rendered in [
            render_json(&invalid).map(|_| ()),
            render_sarif(&invalid).map(|_| ()),
            render_markdown(&invalid).map(|_| ()),
            render_html(&invalid).map(|_| ()),
        ] {
            assert!(matches!(rendered, Err(ReportError::Contract(_))));
        }
    }

    #[test]
    fn json_is_canonical_and_finding_order_is_stable() {
        let first = report(
            ReportStatus::Findings,
            vec![finding("z", "last"), finding("a", "first")],
        );
        let second = report(
            ReportStatus::Findings,
            vec![finding("a", "first"), finding("z", "last")],
        );
        let rendered = render_json(&first).unwrap();
        assert_eq!(rendered, render_json(&second).unwrap());
        assert!(rendered.starts_with("{\"claims\":"));
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["findings"][0]["id"], "a");
        assert_eq!(value["status"], "findings");
    }

    #[test]
    fn empty_incomplete_report_does_not_claim_clean() {
        let report = report(ReportStatus::Incomplete, Vec::new());
        let json = render_json(&report).unwrap();
        let sarif = render_sarif(&report).unwrap();
        let markdown = render_markdown(&report).unwrap();
        let html = render_html(&report).unwrap();
        for rendered in [json, sarif, markdown, html] {
            assert!(rendered.contains("incomplete"));
            assert!(rendered.contains("provider denominator unavailable"));
        }
    }

    #[test]
    fn sarif_contains_identity_status_gaps_targets_claims_and_ordered_results() {
        let report = report(
            ReportStatus::Findings,
            vec![finding("z", "last"), finding("a", "first")],
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_sarif(&report).unwrap()).unwrap();
        let run = &value["runs"][0];
        assert_eq!(run["properties"]["reportId"], "report-1");
        assert_eq!(run["properties"]["status"], "findings");
        assert_eq!(
            run["properties"]["gaps"][0],
            "provider denominator unavailable"
        );
        assert_eq!(run["properties"]["targets"][0], "src/lib.rs");
        assert_eq!(run["properties"]["claims"]["coverage"]["examined"], 0);
        assert_eq!(run["results"][0]["ruleId"], "a");
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
    }

    #[test]
    fn html_and_markdown_escape_untrusted_fields_and_show_provider() {
        let mut item = finding("bad`<id>", "<script>alert(1)</script>");
        item.message = "<img src=x> ` | [link]".into();
        item.provider = Some("<provider>".into());
        item.locations = vec!["file`<x>.rs:1".into()];
        let report = report(ReportStatus::Findings, vec![item]);
        let html = render_html(&report).unwrap();
        let markdown = render_markdown(&report).unwrap();
        assert!(!html.contains("<script>") && html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;provider&gt;") && html.contains("&lt;img src=x&gt;"));
        assert!(!markdown.contains("<script>") && markdown.contains("\\<script\\>"));
        assert!(markdown.contains("\\<provider\\>"));
        assert!(markdown.contains("bad\\`\\<id\\>"));
    }

    #[test]
    fn native_minimize_projection_reaches_json_review_comments_and_ponytail() {
        // Native ingest copies action into title, failureScenario into message,
        // & canonical lens fields into evidence. Lift against actual bytes as
        // audit's report writer does; supplied model confidence is not proof.
        let action = "inline the only implementation";
        let case = "wrapper delegates to its sole implementation";
        let item = Finding {
            id: FindingId::new("minimize-1").unwrap(),
            severity: "medium".into(),
            title: action.into(),
            message: case.into(),
            provider: Some("reasoning.minimize".into()),
            locations: vec!["src/lib.rs:2".into()],
            evidence: BTreeMap::from([
                ("lens".into(), json!("minimize")),
                ("confidence".into(), json!("likely")),
                ("verifyStatus".into(), json!("unverified")),
                ("ponytailTag".into(), json!("yagni")),
                ("action".into(), json!(action)),
                ("failureScenario".into(), json!(case)),
            ]),
        };
        let native = report(ReportStatus::Incomplete, vec![item]);
        let resolve = |path: &str| {
            (path == "src/lib.rs")
                .then(|| b"pub fn wrapper() {\n    implementation();\n}\n".to_vec())
        };
        let diff = |_: &str, _: u32, _: u32| legion_contracts::DiffTag::InDiff;
        let mut context =
            legion_contracts::LiftContext::new(legion_contracts::ReportScope::legacy(), &resolve);
        context.diff_tag = Some(&diff);
        let lifted = ReportV2::from_v1_with(&native, &context).unwrap();
        assert_eq!(
            lifted.findings[0].confidence,
            legion_contracts::Confidence::Likely
        );
        let json: serde_json::Value =
            serde_json::from_str(&render_json_schema(&lifted, 2).unwrap()).unwrap();
        assert_eq!(json["findings"][0]["evidence"]["action"], action);
        assert_eq!(json["findings"][0]["evidence"]["failureScenario"], case);
        let review = render_review(&lifted).unwrap();
        assert!(review.contains(&format!("Supplied fix: {action}")));
        let payload: serde_json::Value =
            serde_json::from_str(&render_github_review(&lifted).unwrap()).unwrap();
        let comments = payload["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["path"], "src/lib.rs");
        assert_eq!(comments[0]["line"], 2);
        let body = comments[0]["body"].as_str().unwrap();
        assert!(body.contains(&format!("Supplied fix: {action}")));
        assert!(body.contains(&format!("Case: {case}")));
        assert!(body.contains("Confidence: `likely`"));
        assert!(!body.contains("proven"));
        let ponytail = render_ponytail(&lifted).unwrap();
        assert!(ponytail.contains(&format!("yagni {case}. {action}. [src/lib.rs:2]")));
        assert!(ponytail.contains("net: unavailable"));
        assert!(ponytail.contains("inspired by Ponytail"));
        assert!(review.contains("inspired by CodeRabbit"));
        assert!(ponytail.contains("provider denominator unavailable"));

        let mut missing = lifted.clone();
        missing.findings[0].evidence.remove("failureScenario");
        let missing_ponytail = render_ponytail(&missing).unwrap();
        assert!(missing_ponytail.contains("Case: unavailable"));
        let mut outside_diff = lifted;
        outside_diff.findings[0].anchor.as_mut().unwrap().state =
            legion_contracts::AnchorState::BeyondDiff;
        let outside: serde_json::Value =
            serde_json::from_str(&render_github_review(&outside_diff).unwrap()).unwrap();
        assert_eq!(outside["comments"].as_array().unwrap().len(), 0);
        assert!(outside["body"].as_str().unwrap().contains(action));
    }
}
