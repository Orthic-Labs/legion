use std::collections::BTreeMap;

use legion_contracts::source_anchor::{
    project_to_pr, validate_evidence_claims, AnchorValidation, PrDiff, PrProjection, SourceSide,
    PR_DIFF_EXTENSION_KEY,
};
use legion_contracts::{AnchorState, Confidence, FindingV2, ReportV2};
use serde_json::{json, Value};

use crate::{escape, status_label};

const INSPIRATION_LABEL: &str = "Review inspired by CodeRabbit";
const MAX_METADATA_BYTES: usize = 8 * 1024;

pub(crate) fn render(report: &ReportV2) -> String {
    let mut output = format!("# {INSPIRATION_LABEL}\n\n");
    output.push_str(&format!(
        "**Status:** {}  \n**Report:** {}  \n**Scope:** {} (head `{}`)\n\n",
        status_label(report.status),
        escape::markdown(report.report_id.as_str()),
        escape::markdown(&report.scope.spec),
        escape::markdown_code(&report.scope.head),
    ));

    output.push_str("## Walkthrough\n\n");
    output.push_str(&format!(
        "{} finding(s), {} positioned anchor(s), {} possible finding(s), & {} recorded gap(s).\n\n",
        report.findings.len(),
        report
            .findings
            .iter()
            .filter(|finding| usable_anchor(finding))
            .count(),
        report
            .findings
            .iter()
            .filter(|finding| finding.confidence == Confidence::Possible)
            .count(),
        report.gaps.len(),
    ));
    if report.findings.is_empty() {
        output.push_str("No findings were recorded.\n\n");
    }
    for finding in ordered(report) {
        output.push_str(&format!(
            "### {} — {}\n\n{}\n\n",
            escape::markdown(&finding.severity),
            escape::markdown(&finding.title),
            escape::markdown(&finding.message),
        ));
        output.push_str(&format!(
            "- Confidence: `{}` (`{}`)\n- Attribution: `{}`\n- Disposition: `{}`\n- Provider: {}\n",
            confidence_label(finding.confidence),
            escape::markdown(&finding.confidence_basis),
            attribution_label(finding),
            disposition_label(finding),
            finding
                .provider
                .as_deref()
                .map(escape::markdown)
                .unwrap_or_else(|| "unavailable".into()),
        ));
        if let Some(anchor) = finding.anchor.as_ref().filter(|_| usable_anchor(finding)) {
            output.push_str(&format!(
                "- Source anchor: {}:{}-{} (`{}`)\n",
                escape::markdown_code(&anchor.path),
                anchor.range.start,
                anchor.range.end,
                anchor_state(anchor.state),
            ));
        } else {
            output.push_str("- Source anchor: unavailable\n");
        }
        match finding.source_anchor_evidence() {
            Some(Ok(evidence)) => {
                output.push_str(&format!(
                    "- Canonical anchor: {}:{}:{}-{}:{} (side `{}`, bytes {}..{}, file `{}`, span `{}`, snapshot {})\n",
                    escape::markdown_code(&evidence.path),
                    evidence.lines.start,
                    evidence.start_column,
                    evidence.lines.end,
                    evidence.end_column,
                    evidence.side.label(),
                    evidence.byte_range.start,
                    evidence.byte_range.end,
                    escape::markdown_code(&evidence.file_digest),
                    escape::markdown_code(&evidence.span_digest),
                    evidence
                        .snapshot_key
                        .as_deref()
                        .map(|key| format!("`{}`", escape::markdown_code(key)))
                        .unwrap_or_else(|| "unrecorded".into()),
                ));
            }
            Some(Err(_)) => output.push_str("- Canonical anchor: invalid\n"),
            None => {}
        }
        if !finding.locations.is_empty() {
            output.push_str("- Reported locations: ");
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
        if let Some(case) = supplied_case(finding) {
            output.push_str(&format!("- Case: {}\n", escape::markdown(&case)));
        }
        if let Some(fix) = supplied_action(finding) {
            output.push_str(&format!("- Supplied fix: {}\n", escape::markdown(&fix)));
        }
        if !finding.evidence.is_empty() {
            output.push_str("\nEvidence supplied with finding:\n\n");
            append_json_block(
                &mut output,
                &bounded_map(&finding.evidence, MAX_METADATA_BYTES),
            );
            output.push('\n');
        }
        output.push('\n');
    }

    if let Some(diagram) = mermaid(report) {
        output.push_str("## Explicit relationships\n\n```mermaid\n");
        output.push_str(&diagram);
        output.push_str("```\n\n");
    }

    output.push_str("## Effort indicators\n\n");
    output.push_str(&format!(
        "| Measure | Count |\n|---|---:|\n| Findings | {} |\n| Positioned anchors | {} |\n| Possible findings | {} |\n| Coverage gaps | {} |\n\n",
        report.findings.len(),
        report.findings.iter().filter(|finding| usable_anchor(finding)).count(),
        report
            .findings
            .iter()
            .filter(|finding| finding.confidence == Confidence::Possible)
            .count(),
        report.gaps.len(),
    ));

    output.push_str("## Pre-merge checks\n\n");
    render_pre_merge(report, &mut output);

    output.push_str("## Coverage, gaps, & provenance\n\n");
    output.push_str(&format!(
        "Status remains `{}`. Unresolved possible findings: {}. Reasoning budget used: `{}`.\n\n",
        status_label(report.status),
        report.unresolved_possible,
        serde_json::to_string(&report.reasoning_budget_used).unwrap_or_else(|_| "{}".into()),
    ));
    output.push_str("Scope, coverage, uncertainty, & provenance:\n\n");
    append_json_block(&mut output, &metadata(report));
    output.push_str("\n");
    output.push_str("Not checked:\n");
    let mut gaps = report.gaps.clone();
    if let Some(notes) = report.claims.get("coverageNotes").and_then(Value::as_array) {
        gaps.extend(notes.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    gaps.sort();
    gaps.dedup();
    if gaps.is_empty() {
        output.push_str("- No coverage gaps or notes were recorded.\n\n");
    } else {
        for gap in gaps {
            output.push_str(&format!("- {}\n", escape::markdown(&gap)));
        }
        output.push('\n');
    }
    output.push_str("Confidence, anchors, coverage, gaps, & provenance are shown above.\n");
    output
}

/// Exact PR diff supplied by the caller under the reserved `prDiff` report
/// extension (or claim). A malformed value is treated as unavailable: it can
/// only suppress inline comments, never enable them.
fn pr_diff(report: &ReportV2) -> Option<PrDiff> {
    let value = report
        .extensions
        .get(PR_DIFF_EXTENSION_KEY)
        .or_else(|| report.claims.get(PR_DIFF_EXTENSION_KEY))?;
    serde_json::from_value(value.clone()).ok()
}

fn side_label(side: SourceSide) -> &'static str {
    match side {
        SourceSide::Selected => "RIGHT",
        SourceSide::Base => "LEFT",
    }
}

pub(crate) fn render_github_review(report: &ReportV2) -> Result<String, crate::ReportError> {
    let diff = pr_diff(report);
    let mut comments = Vec::new();
    for finding in ordered(report) {
        match finding.source_anchor_evidence() {
            // Canonical findings inline only when the exact supplied diff
            // can represent them at the report's head. This renderer holds
            // no scoped bytes: byte-level validation
            // (`validate_evidence_against_bytes`) is the ingest/verifier
            // gate that must already have passed before a report carrying
            // canonical evidence is rendered for a PR. Structural, snapshot
            // & diff representability gates are re-checked here. Anything
            // not inlined remains in the rendered body as a summary finding.
            Some(Ok(evidence)) => {
                let Some(diff) = diff.as_ref() else {
                    continue;
                };
                let claims =
                    validate_evidence_claims(&evidence, report.scope.snapshot_key.as_deref());
                if !claims.is_validated() || !usable_anchor(finding) {
                    continue;
                }
                if finding.anchor.as_ref().is_some_and(|anchor| {
                    anchor.path != evidence.path || anchor.range != evidence.lines
                }) {
                    continue;
                }
                let PrProjection::Inline {
                    path,
                    side,
                    line,
                    start_line,
                } = project_to_pr(
                    &evidence,
                    AnchorValidation::Validated,
                    &report.scope.head,
                    diff,
                )
                else {
                    continue;
                };
                let mut comment = json!({
                    "path": path,
                    "line": line,
                    "side": side_label(side),
                    "body": comment_body(finding),
                });
                if let Some(start_line) = start_line {
                    comment["start_line"] = json!(start_line);
                    comment["start_side"] = json!(side_label(side));
                }
                comments.push(comment);
            }
            // Present-but-malformed canonical evidence never inlines (the
            // public entry point rejects such a report in `validate`).
            Some(Err(_)) => continue,
            // Legacy findings keep the pre-canonical behaviour exactly.
            None => {
                let Some(anchor) = finding.anchor.as_ref() else {
                    continue;
                };
                if anchor.state != AnchorState::InDiff || !usable_anchor(finding) {
                    continue;
                }
                comments.push(json!({
                    "path": anchor.path,
                    "line": anchor.range.end,
                    "side": "RIGHT",
                    "body": comment_body(finding),
                }));
            }
        }
    }
    let payload = json!({
        "body": render(report),
        "event": "COMMENT",
        "comments": comments,
    });
    serde_json::to_string_pretty(&payload).map_err(crate::ReportError::from)
}

fn render_pre_merge(report: &ReportV2, output: &mut String) {
    let checks = report
        .claims
        .get("preMergeChecks")
        .or_else(|| report.claims.get("preMerge"))
        .and_then(Value::as_array);
    let Some(checks) = checks else {
        output.push_str(
            "| Check | Result |\n|---|---|\n| No pre-merge checks supplied | unavailable |\n\n",
        );
        return;
    };
    output.push_str("| Check | Result | Details |\n|---|---|---|\n");
    if checks.is_empty() {
        output.push_str("| No checks recorded | unavailable | — |\n\n");
        return;
    }
    for check in checks {
        let name = check
            .get("name")
            .or_else(|| check.get("command"))
            .and_then(Value::as_str)
            .unwrap_or("unnamed check");
        let result = check
            .get("status")
            .or_else(|| check.get("result"))
            .map(value_label)
            .unwrap_or_else(|| "unavailable".into());
        let details = check
            .get("details")
            .or_else(|| check.get("message"))
            .map(value_label)
            .unwrap_or_else(|| "—".into());
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            escape::markdown(name),
            escape::markdown(&result),
            escape::markdown(&details),
        ));
    }
    output.push('\n');
}

fn graph_context(report: &ReportV2) -> Option<&Value> {
    report
        .extensions
        .get("graphContext")
        .or_else(|| report.claims.get("graphContext"))
}

// Retain the producer's uncertainty & source bindings even when no diagram can
// be rendered. Sorting set-like arrays makes permutation independent output.
fn graph_metadata(report: &ReportV2) -> Option<Value> {
    let mut graph = graph_context(report)?.clone();
    for field in ["edges", "unknowns", "trustedFiles"] {
        if let Some(items) = graph.get_mut(field).and_then(Value::as_array_mut) {
            items.sort_by_key(Value::to_string);
        }
    }
    Some(graph)
}

fn mermaid(report: &ReportV2) -> Option<String> {
    let graph = graph_context(report)?;
    if graph.get("contractVersion").and_then(Value::as_str) != Some("legion-graph/1")
        || graph.get("freshness").and_then(Value::as_str) != Some("bound-to-frozen-covered-bytes")
        || graph
            .get("scopedBytesDigest")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return None;
    }
    let edges = graph.get("edges").and_then(Value::as_array)?;
    if edges.is_empty() {
        return None;
    }
    let mut ordered_edges = edges.clone();
    ordered_edges.sort_by(|left, right| {
        left.get("from")
            .and_then(Value::as_str)
            .cmp(&right.get("from").and_then(Value::as_str))
            .then_with(|| {
                left.get("to")
                    .and_then(Value::as_str)
                    .cmp(&right.get("to").and_then(Value::as_str))
            })
            .then_with(|| left.to_string().cmp(&right.to_string()))
    });
    let mut paths = BTreeMap::<String, String>::new();
    let mut rendered_edges = Vec::new();
    for edge in &ordered_edges {
        let from = edge.get("from").and_then(Value::as_str)?;
        let to = edge.get("to").and_then(Value::as_str)?;
        let evidence = edge.get("evidence")?;
        let source_path = evidence.get("path").and_then(Value::as_str)?;
        let start = evidence.get("startLine").and_then(Value::as_u64)?;
        let end = evidence.get("endLine").and_then(Value::as_u64)?;
        if from.is_empty()
            || to.is_empty()
            || !safe_mermaid_path(from)
            || !safe_mermaid_path(to)
            || source_path != from
            || start == 0
            || end < start
            || evidence
                .get("sourceDigest")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || !matches!(
                edge.get("kind").and_then(Value::as_str),
                Some("imports" | "calls" | "implements" | "tests")
            )
            || !matches!(
                edge.get("confidence").and_then(Value::as_str),
                Some("certain" | "likely" | "possible")
            )
            || !matches!(
                edge.get("source").and_then(Value::as_str),
                Some("blueprint" | "lexical")
            )
        {
            return None;
        }
        rendered_edges.push((
            from.to_owned(),
            to.to_owned(),
            edge["kind"].as_str()?.to_owned(),
            edge["confidence"].as_str()?.to_owned(),
            edge["source"].as_str()?.to_owned(),
        ));
        for path in [from, to] {
            let next = format!("N{}", paths.len());
            paths.entry(path.to_owned()).or_insert(next);
        }
    }
    let mut output = String::from("graph TD\n");
    for (path, id) in &paths {
        output.push_str(&format!("  {id}[\"{path}\"]\n"));
    }
    rendered_edges.sort();
    for (from, to, kind, confidence, source) in rendered_edges {
        let arrow = if confidence == "certain" {
            "-->"
        } else {
            "-.->"
        };
        output.push_str(&format!(
            "  {} {}|{}; {}; {}| {}\n",
            paths[&from], arrow, kind, confidence, source, paths[&to]
        ));
    }
    Some(output)
}

fn ordered(report: &ReportV2) -> Vec<&FindingV2> {
    let mut findings = report.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.id
            .as_str()
            .cmp(right.id.as_str())
            .then_with(|| left.title.cmp(&right.title))
    });
    findings
}

pub(crate) fn usable_anchor(finding: &FindingV2) -> bool {
    finding.anchor.as_ref().is_some_and(|anchor| {
        anchor.state != AnchorState::PositionFailed
            && !anchor.path.is_empty()
            && !anchor.path.starts_with('/')
            && !anchor.path.contains(':')
            && !anchor.path.contains('\\')
            && !anchor.path.contains('\0')
            && anchor
                .path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !anchor.line_hash.trim().is_empty()
            && anchor.range.start > 0
            && anchor.range.end >= anchor.range.start
    })
}

fn evidence_text(finding: &FindingV2, key: &str) -> Option<String> {
    finding
        .evidence
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned)
}

pub(crate) fn supplied_case(finding: &FindingV2) -> Option<String> {
    evidence_text(finding, "failureScenario").or_else(|| evidence_text(finding, "case"))
}

pub(crate) fn supplied_action(finding: &FindingV2) -> Option<String> {
    evidence_text(finding, "action").or_else(|| evidence_text(finding, "fix"))
}

fn comment_body(finding: &FindingV2) -> String {
    let mut body = format!(
        "**{}** — {}\n\n{}",
        escape::markdown(&finding.severity),
        escape::markdown(&finding.title),
        escape::markdown(&finding.message)
    );
    if let Some(case) = supplied_case(finding) {
        body.push_str(&format!("\n\nCase: {}", escape::markdown(&case)));
    }
    if let Some(fix) = supplied_action(finding) {
        body.push_str(&format!("\n\nSupplied fix: {}", escape::markdown(&fix)));
    }
    body.push_str(&format!(
        "\n\nConfidence: `{}` (`{}`); attribution: `{}`; disposition: `{}`.",
        confidence_label(finding.confidence),
        escape::markdown(&finding.confidence_basis),
        attribution_label(finding),
        disposition_label(finding),
    ));
    body
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Proven => "proven",
        Confidence::Likely => "likely",
        Confidence::Possible => "possible",
        Confidence::LegacyUnknown => "legacy-unknown",
    }
}

fn attribution_label(finding: &FindingV2) -> &'static str {
    match finding.attribution {
        legion_contracts::Attribution::Introduced => "introduced",
        legion_contracts::Attribution::RegressedElsewhere => "regressed-elsewhere",
        legion_contracts::Attribution::PreExisting => "pre-existing",
        legion_contracts::Attribution::Unresolved => "unresolved",
        legion_contracts::Attribution::Legacy => "legacy",
    }
}

fn disposition_label(finding: &FindingV2) -> &'static str {
    match finding.disposition {
        legion_contracts::Disposition::Executed => "executed",
        legion_contracts::Disposition::Reused => "reused",
    }
}

fn anchor_state(state: AnchorState) -> &'static str {
    match state {
        AnchorState::Resolved => "resolved",
        AnchorState::InDiff => "in-diff",
        AnchorState::BeyondDiff => "beyond-diff",
        AnchorState::PositionFailed => "position-failed",
    }
}

fn value_label(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn safe_mermaid_path(path: &str) -> bool {
    path.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'-'))
}

fn metadata(report: &ReportV2) -> Value {
    let mut claims = report.claims.clone();
    claims.remove("graphContext");
    json!({
        "status": status_label(report.status),
        "reportId": report.report_id,
        "scope": report.scope,
        "targets": report.targets,
        "coverage": {
            "claims": bounded_map(&claims, MAX_METADATA_BYTES),
            "gaps": report.gaps,
        },
        "uncertainty": {
            "unresolvedPossible": report.unresolved_possible,
            "possibleFindingIds": ordered(report).into_iter()
                .filter(|finding| finding.confidence == Confidence::Possible)
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
        },
        "graphContext": graph_metadata(report),
        "reasoningBudgetUsed": report.reasoning_budget_used,
        "provenance": ordered(report).into_iter().map(|finding| json!({
            "id": finding.id,
            "provider": finding.provider,
            "confidence": confidence_label(finding.confidence),
            "confidenceBasis": finding.confidence_basis,
            "anchor": finding.anchor,
            "attribution": attribution_label(finding),
            "disposition": disposition_label(finding),
        })).collect::<Vec<_>>(),
    })
}

fn bounded_map(fields: &BTreeMap<String, Value>, max_bytes: usize) -> Value {
    let mut included = BTreeMap::new();
    let mut omitted = Vec::new();
    let mut used = 0usize;
    for (key, value) in fields {
        let encoded_len = value.to_string().len().saturating_add(key.len());
        if used.saturating_add(encoded_len) <= max_bytes {
            used += encoded_len;
            included.insert(key.clone(), value.clone());
        } else {
            omitted.push(key.clone());
        }
    }
    json!({"values": included, "omittedKeys": omitted})
}

fn append_json_block(output: &mut String, value: &Value) {
    let serialized = serde_json::to_string_pretty(value).unwrap_or_default();
    let longest = serialized
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(3.max(longest + 1));
    output.push_str(&fence);
    output.push_str("json\n");
    output.push_str(&serialized);
    output.push('\n');
    output.push_str(&fence);
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use legion_contracts::{
        Anchor, Attribution, Confidence, Disposition, FindingId, LineRange, ReasoningBudgetUsed,
        ReportId, ReportScope, ReportStatus,
    };

    use super::*;

    fn report() -> ReportV2 {
        ReportV2 {
            schema_version: 2,
            report_id: ReportId::new("review-1").unwrap(),
            status: ReportStatus::Incomplete,
            findings: Vec::new(),
            gaps: vec!["provider coverage missing".into()],
            claims: BTreeMap::from([("coverageNotes".into(), json!(["linux runner unavailable"]))]),
            targets: vec!["src/lib.rs".into()],
            scope: ReportScope::legacy(),
            unresolved_possible: 0,
            reasoning_budget_used: ReasoningBudgetUsed::default(),
            extensions: BTreeMap::new(),
        }
    }

    fn finding(id: &str, anchor: Option<Anchor>) -> FindingV2 {
        FindingV2 {
            id: FindingId::new(id).unwrap(),
            severity: "high".into(),
            title: "unverified finding".into(),
            message: "source-derived observation".into(),
            provider: Some("scanner".into()),
            locations: vec!["src/lib.rs:9".into()],
            evidence: BTreeMap::new(),
            confidence: Confidence::Possible,
            confidence_basis: "reflection-unresolved".into(),
            anchor,
            attribution: Attribution::Unresolved,
            disposition: Disposition::Executed,
        }
    }

    fn anchor(state: AnchorState) -> Anchor {
        Anchor {
            path: "src/lib.rs".into(),
            range: LineRange { start: 9, end: 9 },
            line_hash: "sha256:line".into(),
            state,
        }
    }

    #[test]
    fn keeps_incomplete_unanchored_and_unverified_findings_visible() {
        let mut report = report();
        report.findings.push(finding("f-1", None));
        report.unresolved_possible = 1;
        let rendered = render(&report);
        assert!(rendered.contains("Status:** incomplete"));
        assert!(rendered.contains("Confidence: `possible` (`reflection-unresolved`)"));
        assert!(rendered.contains("Source anchor: unavailable"));
        assert!(rendered.contains("provider coverage missing"));
        assert!(rendered.contains("linux runner unavailable"));
        assert!(!rendered.contains("```mermaid"));
        assert!(rendered.contains("No pre-merge checks supplied"));
    }

    #[test]
    fn review_escapes_untrusted_text_and_prints_only_supplied_case_and_fix() {
        let mut report = report();
        let mut item = finding("f-1", Some(anchor(AnchorState::InDiff)));
        item.title = "<script>bad</script>".into();
        item.message = "message with `pipes |`".into();
        item.evidence = BTreeMap::from([
            ("failureScenario".into(), json!("input x causes failure")),
            ("action".into(), json!("return early")),
        ]);
        report.findings.push(item);
        report.unresolved_possible = 1;
        let rendered = render(&report);
        assert!(!rendered.contains("<script>"));
        assert!(rendered.contains("input x causes failure"));
        assert!(rendered.contains("Supplied fix: return early"));
        let payload: Value = serde_json::from_str(&render_github_review(&report).unwrap()).unwrap();
        assert_eq!(payload["comments"][0]["line"], 9);
        assert_eq!(payload["comments"][0]["side"], "RIGHT");
        assert!(payload["comments"][0]["body"]
            .as_str()
            .unwrap()
            .contains("return early"));
    }

    #[test]
    fn github_review_excludes_unanchored_and_beyond_diff_findings() {
        let mut report = report();
        let mut invalid_range = finding("c", Some(anchor(AnchorState::InDiff)));
        invalid_range.anchor.as_mut().unwrap().state = AnchorState::PositionFailed;
        invalid_range.anchor.as_mut().unwrap().range.end = 8;
        report.findings = vec![
            finding("b", Some(anchor(AnchorState::BeyondDiff))),
            finding("a", None),
            invalid_range,
        ];
        report.unresolved_possible = 3;
        let payload: Value = serde_json::from_str(&render_github_review(&report).unwrap()).unwrap();
        assert_eq!(payload["comments"].as_array().unwrap().len(), 0);
    }

    fn canonical_report(side: legion_contracts::source_anchor::SourceSide) -> ReportV2 {
        use legion_contracts::source_anchor::{build_evidence, line_byte_range};
        const BYTES: &[u8] = b"1\n2\n3\n4\n5\n6\n7\n8\nnine\n10\n";
        let mut report = report();
        report.scope.head = "head-1".into();
        report.scope.snapshot_key = Some("snap-1".into());
        let mut item = finding("f-1", Some(anchor(AnchorState::InDiff)));
        let evidence = build_evidence(
            "src/lib.rs",
            side,
            None,
            Some("snap-1"),
            BYTES,
            line_byte_range(BYTES, LineRange { start: 9, end: 9 }).unwrap(),
        )
        .unwrap();
        item.set_source_anchor_evidence(&evidence).unwrap();
        report.findings.push(item);
        report.unresolved_possible = 1;
        report
    }

    fn with_pr_diff(report: &mut ReportV2, head: &str, base: bool) {
        report.extensions.insert(
            "prDiff".into(),
            json!({
                "headOid": head,
                "files": [{
                    "basePath": "src/lib.rs",
                    "headPath": if base { Value::Null } else { json!("src/lib.rs") },
                    "baseHunks": [{"start": 8, "end": 10}],
                    "headHunks": [{"start": 8, "end": 10}],
                }],
            }),
        );
    }

    #[test]
    fn canonical_anchor_inlines_only_on_exact_supplied_diff() {
        use legion_contracts::source_anchor::SourceSide;
        // No supplied diff: no fabricated inline comment, finding stays in
        // the summary body with its canonical coordinates.
        let report = canonical_report(SourceSide::Selected);
        let payload: Value =
            serde_json::from_str(&render_github_review(&report).unwrap()).unwrap();
        assert_eq!(payload["comments"].as_array().unwrap().len(), 0);
        let body = payload["body"].as_str().unwrap();
        assert!(body.contains("Canonical anchor:"));
        assert!(body.contains("unverified finding"));
        // Exact diff at the report head: RIGHT inline comment.
        let mut report = canonical_report(SourceSide::Selected);
        with_pr_diff(&mut report, "head-1", false);
        let payload: Value =
            serde_json::from_str(&render_github_review(&report).unwrap()).unwrap();
        let comments = payload["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["path"], "src/lib.rs");
        assert_eq!(comments[0]["line"], 9);
        assert_eq!(comments[0]["side"], "RIGHT");
        assert!(comments[0].get("start_line").is_none());
        // PR head moved: no inline comment on a stale diff.
        let mut report = canonical_report(SourceSide::Selected);
        with_pr_diff(&mut report, "head-2", false);
        let payload: Value =
            serde_json::from_str(&render_github_review(&report).unwrap()).unwrap();
        assert_eq!(payload["comments"].as_array().unwrap().len(), 0);
        assert!(payload["body"].as_str().unwrap().contains("unverified finding"));
    }

    #[test]
    fn canonical_base_anchor_uses_left_side_of_deleted_file() {
        use legion_contracts::source_anchor::SourceSide;
        let mut report = canonical_report(SourceSide::Base);
        with_pr_diff(&mut report, "head-1", true);
        let payload: Value =
            serde_json::from_str(&render_github_review(&report).unwrap()).unwrap();
        let comments = payload["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["side"], "LEFT");
        assert_eq!(comments[0]["path"], "src/lib.rs");
        assert_eq!(comments[0]["line"], 9);
    }

    #[test]
    fn graph_edges_keep_confidence_source_evidence_and_unknown_floor() {
        let mut report = report();
        report.extensions.insert("graphContext".into(), json!({
            "contractVersion":"legion-graph/1",
            "blueprintVersion":"fixture-v1",
            "freshness":"bound-to-frozen-covered-bytes",
            "scopedBytesDigest":"sha256:scope",
            "coveredFilesDigest":"sha256:covered",
            "resolverConfigDigest":"sha256:resolver",
            "coverageFloor":"provenance-bound-blueprint-plus-lexical-floor",
            "trustedFiles":["src/z.rs"],
            "unknowns":[{"path":null,"cause":"dynamic relationships remain unknown"}],
            "truncated":true,
            "edges":[
                {"from":"src/z.rs","to":"src/a.rs","kind":"imports","confidence":"certain","source":"blueprint","evidence":{"path":"src/z.rs","startLine":2,"endLine":2,"sourceDigest":"sha256:blueprint"}},
                {"from":"src/z.rs","to":"src/b.rs","kind":"imports","confidence":"possible","source":"lexical","evidence":{"path":"src/z.rs","startLine":3,"endLine":3,"sourceDigest":"sha256:lexical"}},
                {"from":"src/z.rs","to":"src/c.rs","kind":"calls","confidence":"likely","source":"blueprint","evidence":{"path":"src/z.rs","startLine":4,"endLine":4,"sourceDigest":"sha256:likely"}}
            ]
        }));
        let rendered = render(&report);
        assert!(rendered.contains("-->|imports; certain; blueprint|"));
        assert!(rendered.contains("-.->|imports; possible; lexical|"));
        assert!(rendered.contains("-.->|calls; likely; blueprint|"));
        let metadata = metadata(&report);
        assert_eq!(
            metadata["graphContext"]["coverageFloor"],
            "provenance-bound-blueprint-plus-lexical-floor"
        );
        assert_eq!(metadata["graphContext"]["truncated"], true);
        assert_eq!(
            metadata["graphContext"]["unknowns"][0]["cause"],
            "dynamic relationships remain unknown"
        );
        assert!(metadata["graphContext"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["evidence"]["sourceDigest"] == "sha256:lexical"));
        let graph = report.extensions.get_mut("graphContext").unwrap();
        graph["edges"].as_array_mut().unwrap().reverse();
        assert_eq!(rendered, render(&report));
        report.extensions.get_mut("graphContext").unwrap()["freshness"] = json!("stale");
        let stale = render(&report);
        assert!(!stale.contains("```mermaid"));
        assert!(stale.contains("dynamic relationships remain unknown"));
        assert!(stale.contains("sha256:lexical"));
    }
}
