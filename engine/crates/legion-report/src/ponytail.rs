use std::collections::BTreeMap;

use legion_contracts::{Confidence, FindingV2, ReportV2};
use serde_json::{json, Value};

use crate::review::{supplied_action, supplied_case, usable_anchor};
use crate::{escape, status_label};

const TAGS: [&str; 5] = ["delete", "stdlib", "native", "yagni", "shrink"];
const MAX_METADATA_BYTES: usize = 8 * 1024;

// The report schema has no authoritative marker convention, so marker aliases
// aren't inferred; original marker data appears only in bounded finding evidence.

pub(crate) fn render(report: &ReportV2) -> String {
    let mut output = format!(
        "# Review inspired by Ponytail\n\n**Status:** `{}`\n\n",
        status_label(report.status)
    );
    output.push_str("## Findings\n\n");
    let mut findings = report.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        cut_estimate(right)
            .cmp(&cut_estimate(left))
            .then_with(|| left.id.as_str().cmp(right.id.as_str()))
    });
    let mut emitted = 0;
    let mut complete_estimates = true;
    let mut lines = 0i64;
    let mut deps = 0i64;
    let mut files = 0i64;
    let mut unqualified = Vec::new();
    for finding in findings {
        let Some(tag) = tag(finding) else {
            unqualified.push(finding);
            continue;
        };
        let Some(cut) = cut_description(finding) else {
            unqualified.push(finding);
            continue;
        };
        let Some(replacement) =
            text_field(finding, "replacement").or_else(|| supplied_action(finding))
        else {
            unqualified.push(finding);
            continue;
        };
        let Some(anchor) = finding.anchor.as_ref().filter(|_| usable_anchor(finding)) else {
            unqualified.push(finding);
            continue;
        };
        output.push_str(&format!(
            "{} {}. {}. [{}:{}]\n",
            tag,
            line_text(&cut),
            line_text(&replacement),
            escape::markdown(&anchor.path),
            anchor.range.start,
        ));
        output.push_str(&format!(
            "  Confidence: `{}` (`{}`); attribution: `{}`; disposition: `{}`.\n",
            confidence(finding),
            escape::markdown(&finding.confidence_basis),
            attribution(finding),
            disposition(finding),
        ));
        if let Some(case) = supplied_case(finding) {
            output.push_str(&format!("  Case: {}\n", escape::markdown(&case)));
        } else {
            output.push_str("  Case: unavailable\n");
        }
        if let Some(fix) = supplied_action(finding) {
            output.push_str(&format!("  Supplied fix: {}\n", escape::markdown(&fix)));
        }
        if !finding.evidence.is_empty() {
            output.push_str("  Supplied finding metadata:\n\n");
            append_json_block(
                &mut output,
                &bounded_map(&finding.evidence, MAX_METADATA_BYTES),
            );
        }
        match estimate(finding) {
            Some((finding_lines, finding_deps, finding_files)) => {
                if let (Some(new_lines), Some(new_deps), Some(new_files)) = (
                    lines.checked_add(finding_lines),
                    deps.checked_add(finding_deps),
                    files.checked_add(finding_files),
                ) {
                    lines = new_lines;
                    deps = new_deps;
                    files = new_files;
                } else {
                    complete_estimates = false;
                }
            }
            None => complete_estimates = false,
        }
        emitted += 1;
    }
    if emitted == 0 {
        output.push_str("No fully anchored five-tag cut findings were supplied.\n");
        complete_estimates = false;
    }
    output.push('\n');

    if !unqualified.is_empty() {
        complete_estimates = false;
        output.push_str("## Findings without a complete Ponytail line\n\n");
        output.push_str("Tag, cut, replacement, or verified source anchor is unavailable; original finding data follows.\n\n");
        for finding in unqualified {
            output.push_str(&format!(
                "- `{}` — {} — {}\n",
                escape::markdown(finding.id.as_str()),
                escape::markdown(&finding.title),
                escape::markdown(&finding.message),
            ));
            output.push_str(&format!(
                "  Confidence: `{}` (`{}`); attribution: `{}`; disposition: `{}`.\n",
                confidence(finding),
                escape::markdown(&finding.confidence_basis),
                attribution(finding),
                disposition(finding),
            ));
            if let Some(case) = supplied_case(finding) {
                output.push_str(&format!("  Case: {}\n", escape::markdown(&case)));
            } else {
                output.push_str("  Case: unavailable\n");
            }
            output.push_str("  Evidence:\n\n");
            append_json_block(
                &mut output,
                &bounded_map(&finding.evidence, MAX_METADATA_BYTES),
            );
            output.push('\n');
        }
        output.push('\n');
    }

    let net = if complete_estimates {
        format!("net: -{lines} lines, -{deps} deps, -{files} files possible.\n")
    } else {
        "net: unavailable (complete measured cut estimates were not supplied for every finding).\n"
            .into()
    };
    output.push_str(&format!(
        "Report status `{}`; unresolved possible findings: {}; coverage gaps: {}.\n\n",
        status_label(report.status),
        report.unresolved_possible,
        report.gaps.len(),
    ));
    output.push_str(&crate::assurance_view::markdown(
        &crate::assurance_view::view(&report.extensions),
        false,
    ));
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
    output.push_str("Scope, coverage, uncertainty, & provenance:\n\n");
    append_json_block(&mut output, &metadata(report));
    output.push('\n');
    output.push_str(&net);
    output
}

fn line_text(text: &str) -> String {
    escape::markdown(text).replace('\r', " ").replace('\n', " ")
}

fn tag(finding: &FindingV2) -> Option<&'static str> {
    let raw = finding.evidence.get("ponytailTag")?.as_str()?;
    TAGS.iter().copied().find(|tag| *tag == raw)
}

// Native ingest uses action as the title when no separate title was supplied.
// In that case failureScenario carries the observed cut; action is remediation.
fn cut_description(finding: &FindingV2) -> Option<String> {
    if let Some(cut) = text_field(finding, "whatToCut") {
        return Some(cut);
    }
    let action = supplied_action(finding);
    if !finding.title.trim().is_empty()
        && finding.title != "Lens finding"
        && Some(finding.title.as_str()) != action.as_deref()
    {
        return Some(finding.title.clone());
    }
    supplied_case(finding).or_else(|| {
        (!finding.message.trim().is_empty() && finding.message != "Lens reported a finding")
            .then(|| finding.message.clone())
    })
}

fn text_field(finding: &FindingV2, key: &str) -> Option<String> {
    finding
        .evidence
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned)
}

fn estimate(finding: &FindingV2) -> Option<(i64, i64, i64)> {
    let estimate = finding.evidence.get("cutEstimate")?;
    let values = (
        estimate.get("lines")?.as_i64()?,
        estimate.get("deps")?.as_i64()?,
        estimate.get("files")?.as_i64()?,
    );
    (values.0 >= 0 && values.1 >= 0 && values.2 >= 0).then_some(values)
}

fn cut_estimate(finding: &FindingV2) -> Option<(i64, i64, i64)> {
    estimate(finding).map(|(lines, deps, files)| (lines, deps, files))
}

fn ordered(report: &ReportV2) -> Vec<&FindingV2> {
    let mut findings = report.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    findings
}

fn metadata(report: &ReportV2) -> Value {
    json!({
        "status": status_label(report.status),
        "reportId": report.report_id,
        "scope": report.scope,
        "targets": report.targets,
        "coverage": {
            "claims": bounded_map(&report.claims, MAX_METADATA_BYTES),
            "gaps": report.gaps,
        },
        "uncertainty": {
            "unresolvedPossible": report.unresolved_possible,
            "possibleFindingIds": ordered(report).into_iter()
                .filter(|finding| finding.confidence == Confidence::Possible)
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
        },
        "reasoningBudgetUsed": report.reasoning_budget_used,
        "provenance": ordered(report).into_iter().map(|finding| json!({
            "id": finding.id,
            "provider": finding.provider,
            "confidence": confidence(finding),
            "confidenceBasis": finding.confidence_basis,
            "anchor": finding.anchor,
            "attribution": attribution(finding),
            "disposition": disposition(finding),
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

fn confidence(finding: &FindingV2) -> &'static str {
    match finding.confidence {
        legion_contracts::Confidence::Proven => "proven",
        legion_contracts::Confidence::Likely => "likely",
        legion_contracts::Confidence::Possible => "possible",
        legion_contracts::Confidence::LegacyUnknown => "legacy-unknown",
    }
}

fn attribution(finding: &FindingV2) -> &'static str {
    match finding.attribution {
        legion_contracts::Attribution::Introduced => "introduced",
        legion_contracts::Attribution::RegressedElsewhere => "regressed-elsewhere",
        legion_contracts::Attribution::PreExisting => "pre-existing",
        legion_contracts::Attribution::Unresolved => "unresolved",
        legion_contracts::Attribution::Legacy => "legacy",
    }
}

fn disposition(finding: &FindingV2) -> &'static str {
    match finding.disposition {
        legion_contracts::Disposition::Executed => "executed",
        legion_contracts::Disposition::Reused => "reused",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use legion_contracts::{
        Anchor, AnchorState, Attribution, Confidence, Disposition, FindingId, LineRange,
        ReasoningBudgetUsed, ReportId, ReportScope, ReportStatus,
    };
    use serde_json::{json, Value};

    use super::*;

    fn report() -> ReportV2 {
        ReportV2 {
            schema_version: 2,
            report_id: ReportId::new("ponytail-1").unwrap(),
            status: ReportStatus::Incomplete,
            findings: Vec::new(),
            gaps: vec!["coverage:partial".into()],
            claims: BTreeMap::from([("coverageNotes".into(), json!(["provider:degraded"]))]),
            targets: vec!["src/lib.rs".into()],
            scope: ReportScope::legacy(),
            unresolved_possible: 0,
            reasoning_budget_used: ReasoningBudgetUsed::default(),
            extensions: BTreeMap::new(),
        }
    }

    fn finding(id: &str, line: Option<u32>) -> FindingV2 {
        FindingV2 {
            id: FindingId::new(id).unwrap(),
            severity: "medium".into(),
            title: "observed issue".into(),
            message: "keep original data".into(),
            provider: Some("reviewer".into()),
            locations: vec!["src/lib.rs:4".into()],
            evidence: BTreeMap::new(),
            confidence: Confidence::Likely,
            confidence_basis: "anchored-hit".into(),
            anchor: line.map(|line| Anchor {
                path: "src/lib.rs".into(),
                range: LineRange {
                    start: line,
                    end: line,
                },
                line_hash: "sha256:line".into(),
                state: legion_contracts::AnchorState::InDiff,
            }),
            attribution: Attribution::Introduced,
            disposition: Disposition::Executed,
        }
    }

    #[test]
    fn incomplete_unanchored_findings_remain_unqualified_and_ledger_is_rendered() {
        let mut report = report();
        report.findings.push(finding("f1", None));
        let rendered = render(&report);
        assert!(rendered.contains("without a complete Ponytail line"));
        assert!(rendered.contains("Evidence:"));
        assert!(rendered.contains("net: unavailable"));
        assert!(rendered.contains("Not checked:"));
        assert!(rendered.contains("coverage:partial"));
        assert!(rendered.contains("provider:degraded"));
        assert!(rendered.contains("inspired by Ponytail"));
    }

    #[test]
    fn native_tag_case_action_and_measured_estimate_use_exact_line_template() {
        let mut report = report();
        let mut item = finding("f1", Some(4));
        item.title = "duplicate branch".into();
        item.evidence = BTreeMap::from([
            ("lens".into(), json!("minimize")),
            ("ponytailTag".into(), json!("shrink")),
            ("action".into(), json!("use one shared path")),
            ("failureScenario".into(), json!("duplicate input")),
            ("cutEstimate".into(), json!({"lines":7,"deps":0,"files":0})),
        ]);
        report.findings.push(item);
        let rendered = render(&report);
        assert!(rendered.contains("shrink duplicate branch. use one shared path. [src/lib.rs:4]"));
        assert!(rendered.contains("Case: duplicate input"));
        assert!(rendered.contains("Supplied fix: use one shared path"));
        assert!(rendered.contains("net: -7 lines, -0 deps, -0 files possible."));
    }

    #[test]
    fn measured_candidates_sort_before_unmeasured_and_other_findings_keep_identity() {
        let mut report = report();
        let mut measured = finding("z", Some(5));
        measured.evidence = BTreeMap::from([
            ("ponytailTag".into(), json!("delete")),
            ("whatToCut".into(), json!("larger")),
            ("replacement".into(), json!("nothing")),
            ("cutEstimate".into(), json!({"lines":12,"deps":0,"files":1})),
        ]);
        let mut other = finding("a", None);
        other.title = "unrelated security finding".into();
        other.confidence = Confidence::Possible;
        measured.confidence = Confidence::Possible;
        report.unresolved_possible = 2;
        report.findings = vec![other, measured];
        let rendered = render(&report);
        assert!(
            rendered.find("delete larger").unwrap()
                < rendered.find("unrelated security finding").unwrap()
        );
        let metadata: Value = serde_json::from_str(
            &rendered
                .split("```json\n")
                .last()
                .unwrap()
                .split("\n```")
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(metadata["provenance"].as_array().unwrap().len(), 2);
        let mut reversed = report.clone();
        reversed.findings.reverse();
        assert_eq!(rendered, render(&reversed));
    }

    #[test]
    fn missing_case_action_anchor_and_estimates_stay_explicit() {
        let mut report = report();
        let mut missing_case = finding("case", Some(4));
        missing_case.title = "duplicate branch".into();
        missing_case.evidence = BTreeMap::from([
            ("ponytailTag".into(), json!("shrink")),
            ("action".into(), json!("combine branches")),
        ]);
        let mut missing_action = missing_case.clone();
        missing_action.id = FindingId::new("action").unwrap();
        missing_action.evidence.remove("action");
        let mut failed_anchor = missing_case.clone();
        failed_anchor.id = FindingId::new("anchor").unwrap();
        failed_anchor.anchor.as_mut().unwrap().state = AnchorState::PositionFailed;
        report.findings = vec![missing_case, missing_action, failed_anchor];
        let rendered = render(&report);
        assert_eq!(
            rendered
                .matches("shrink duplicate branch. combine branches. [")
                .count(),
            1
        );
        assert!(rendered.contains("Case: unavailable"));
        assert!(rendered.contains("without a complete Ponytail line"));
        assert!(rendered.contains("net: unavailable"));
        assert!(rendered.contains("coverage:partial"));
        assert!(!rendered.contains("confirmed"));
    }
}
