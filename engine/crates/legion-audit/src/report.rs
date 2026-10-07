use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{Finding, FindingId, ReportId, ReportStatus, ReportV1};
use serde_json::{json, Value};

use crate::{error::AuditError, execution::ExecutionReport};

pub fn canonical_report(
    repository_id: &str,
    execution: &ExecutionReport,
) -> Result<ReportV1, AuditError> {
    let mut finding_ids = BTreeSet::new();
    let mut findings = Vec::new();
    let mut gaps = execution.gaps.clone();
    let mut semantic_review = serde_json::Map::new();
    let mut change_risk = Value::Null;
    if execution.plan_signature.is_none() {
        gaps.push("unsigned-plan".into());
    }
    for provider in &execution.results {
        let axis = match provider.provider.as_str() {
            "reasoning.correctness" => Some("spec"),
            "reasoning.ai-slop" => Some("standards"),
            _ => None,
        };
        if let Some(axis) = axis {
            let review = provider
                .result
                .details
                .get("semanticReview")
                .cloned()
                .unwrap_or_else(|| {
                    json!({
                        "axis": axis,
                        "status": "unproven",
                        "reason": "Provider did not return a semantic review verdict",
                        "sources": [],
                    })
                });
            if review.get("status").and_then(Value::as_str) == Some("unproven") {
                gaps.push(format!("semantic-review-unproven:{axis}"));
            }
            semantic_review.insert(axis.into(), review);
        }
        if provider.provider == "reasoning.architecture" {
            change_risk = provider
                .result
                .details
                .get("changeRisk")
                .cloned()
                .unwrap_or_else(|| {
                    json!({
                        "reversibility": "unknown",
                        "blastRadius": "unknown",
                        "reason": "Provider did not return change-risk evidence",
                        "beforeEvidence": [],
                        "afterEvidence": [],
                    })
                });
        }
        gaps.extend(
            provider
                .result
                .degradation
                .iter()
                .map(|gap| format!("provider-degradation:{}:{gap}", provider.provider)),
        );
        for finding in &provider.result.findings {
            if !finding_ids.insert(finding.id.clone()) {
                gaps.push(format!("duplicate-finding-id:{}", finding.id));
                continue;
            }
            let mut evidence =
                detail_object(&provider.result.details, "findingEvidence", &finding.id);
            if let Some(lens_finding) = provider
                .result
                .details
                .get("lensFindings")
                .and_then(Value::as_array)
                .and_then(|values| {
                    values.iter().find(|value| {
                        value.get("id").and_then(Value::as_str) == Some(finding.id.as_str())
                    })
                })
            {
                for field in [
                    "reviewAxis",
                    "sourceQuote",
                    "sourceLocation",
                    "disposition",
                    "changeAttribution",
                ] {
                    if let Some(value) = lens_finding.get(field) {
                        evidence.insert(field.into(), value.clone());
                    }
                }
            }
            let locations = provider
                .result
                .details
                .get("findingLocations")
                .and_then(Value::as_object)
                .and_then(|values| values.get(finding.id.as_str()))
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let title = detail_string(
                &provider.result.details,
                "findingTitles",
                &finding.id,
                "Audit finding",
            );
            let message = detail_string(
                &provider.result.details,
                "findingMessages",
                &finding.id,
                "Provider reported a finding",
            );
            findings.push(Finding {
                id: FindingId::new(finding.id.as_str())?,
                severity: finding.severity.clone(),
                title,
                message,
                provider: Some(provider.provider.clone()),
                locations,
                evidence,
            });
        }
    }
    gaps.sort();
    gaps.dedup();
    findings.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    let status = if !gaps.is_empty() {
        ReportStatus::Incomplete
    } else if findings.is_empty() {
        ReportStatus::Clean
    } else {
        ReportStatus::Findings
    };
    let result_count = execution.results.len();
    let complete_count = execution
        .results
        .iter()
        .filter(|result| result.result.complete && !result.skipped)
        .count();
    let report = ReportV1 {
        schema_version: 1,
        report_id: ReportId::new(format!(
            "audit-{}",
            execution.plan_digest.trim_start_matches("sha256:")
        ))?,
        status,
        findings,
        gaps,
        claims: BTreeMap::from([
            ("planDigest".into(), json!(execution.plan_digest)),
            ("planSignature".into(), json!(execution.plan_signature)),
            ("inventoryGeneration".into(), json!(execution.generation)),
            ("inventoryDigest".into(), json!(execution.inventory_digest)),
            (
                "plannedProviders".into(),
                json!(execution.planned_providers),
            ),
            ("executedProviderCount".into(), json!(result_count)),
            ("completeProviderCount".into(), json!(complete_count)),
            ("selectedLenses".into(), json!(execution.selected_lenses)),
            // `lensesRan` and `reasoningLensesRan` both mean reasoning lenses
            // that completed. Lens tags on deterministic providers are
            // coverage tags only and are reported separately.
            ("lensesRan".into(), json!(execution.lenses_ran)),
            ("reasoningLensesRan".into(), json!(execution.lenses_ran)),
            (
                "selectedReasoningLenses".into(),
                json!(execution.selected_reasoning_lenses),
            ),
            (
                "reasoningLensesPending".into(),
                json!(execution
                    .pending_host
                    .iter()
                    .map(|provider| json!({"provider": provider, "status": "pending-host"}))
                    .collect::<Vec<_>>()),
            ),
            (
                "deterministicLensTagCounts".into(),
                json!(execution.deterministic_lens_tags),
            ),
        ]),
        targets: vec![repository_id.to_owned()],
        extensions: BTreeMap::from([
            (
                "providerResults".into(),
                serde_json::to_value(&execution.results)
                    .map_err(|error| AuditError::Invalid(error.to_string()))?,
            ),
            ("semanticReview".into(), Value::Object(semantic_review)),
            ("changeRisk".into(), change_risk),
        ]),
    };
    report.validate()?;
    Ok(report)
}

fn detail_object(
    details: &BTreeMap<String, Value>,
    field: &str,
    finding_id: &FindingId,
) -> BTreeMap<String, Value> {
    details
        .get(field)
        .and_then(Value::as_object)
        .and_then(|values| values.get(finding_id.as_str()))
        .and_then(Value::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn detail_string(
    details: &BTreeMap<String, Value>,
    field: &str,
    finding_id: &FindingId,
    fallback: &str,
) -> String {
    details
        .get(field)
        .and_then(Value::as_object)
        .and_then(|values| values.get(finding_id.as_str()))
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ProviderExecution;
    use legion_contracts::{Coverage, FindingRef, ProviderId, ProviderResult, ProviderStatus};

    fn execution(results: Vec<ProviderExecution>) -> ExecutionReport {
        ExecutionReport {
            plan_digest: format!("sha256:{}", "a".repeat(64)),
            plan_signature: Some("signed".into()),
            generation: "test-generation".into(),
            inventory_digest: format!("sha256:{}", "b".repeat(64)),
            planned_providers: results.iter().map(|row| row.provider.clone()).collect(),
            results,
            selected_lenses: Vec::new(),
            lenses_ran: Vec::new(),
            selected_reasoning_lenses: Vec::new(),
            pending_host: Vec::new(),
            deterministic_lens_tags: BTreeMap::new(),
            gaps: Vec::new(),
        }
    }

    fn provider(id: &str, details: Value) -> ProviderExecution {
        ProviderExecution {
            provider: id.into(),
            skipped: false,
            result: ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(id).unwrap(),
                applicable: true,
                required: true,
                status: ProviderStatus::Complete,
                complete: true,
                coverage: Some(Coverage {
                    denominator_digest: format!("sha256:{}", "c".repeat(64)),
                    expected: 1,
                    examined: 1,
                    gaps: Vec::new(),
                }),
                findings: Vec::new(),
                coverage_gaps: Vec::new(),
                degradation: Vec::new(),
                details: serde_json::from_value(details).unwrap(),
            },
        }
    }

    #[test]
    fn report_preserves_independent_axes_and_finding_attribution() {
        let mut spec = provider(
            "reasoning.correctness",
            json!({
                "semanticReview": {"axis":"spec", "status":"findings", "reason":"Missing required behavior", "sources":[{"location":"SPEC.md:4", "quote":"Reject empty input"}]},
                "lensFindings": [{"id":"spec-1", "reviewAxis":"spec", "sourceLocation":"SPEC.md:4", "sourceQuote":"Reject empty input", "disposition":"missing", "changeAttribution":{"status":"unknown", "reason":"No baseline", "baselineEvidence":[]}}]
            }),
        );
        spec.result.findings.push(FindingRef {
            id: FindingId::new("spec-1").unwrap(),
            severity: "high".into(),
        });
        let standards = provider(
            "reasoning.ai-slop",
            json!({
                "semanticReview": {"axis":"standards", "status":"pass", "reason":"Documented standards satisfied", "sources":[{"location":"AGENTS.md:2", "quote":"Validate public inputs"}]}
            }),
        );
        let risk = json!({"reversibility":"unknown", "blastRadius":"input validation", "reason":"No baseline", "beforeEvidence":[], "afterEvidence":[]});
        let architecture = provider("reasoning.architecture", json!({"changeRisk":risk}));
        let report =
            canonical_report("fixture", &execution(vec![spec, standards, architecture])).unwrap();
        assert_eq!(report.status, ReportStatus::Findings);
        assert_eq!(
            report.extensions["semanticReview"]["spec"]["status"],
            "findings"
        );
        assert_eq!(
            report.extensions["semanticReview"]["standards"]["status"],
            "pass"
        );
        assert_eq!(report.extensions["changeRisk"], risk);
        assert_eq!(
            report.findings[0].evidence["changeAttribution"]["status"],
            "unknown"
        );
        assert_eq!(report.findings[0].evidence["sourceLocation"], "SPEC.md:4");
    }

    #[test]
    fn missing_semantic_verdict_cannot_become_clean() {
        let report = canonical_report(
            "fixture",
            &execution(vec![provider("reasoning.correctness", json!({}))]),
        )
        .unwrap();
        assert_eq!(report.status, ReportStatus::Incomplete);
        assert!(report
            .gaps
            .contains(&"semantic-review-unproven:spec".into()));
    }
}
