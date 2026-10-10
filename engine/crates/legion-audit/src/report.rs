use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{Finding, FindingId, ReportId, ReportStatus, ReportV1};
use serde_json::{json, Value};

use crate::{
    error::AuditError,
    execution::{ExecutionReport, OWNERSHIP_PROVIDER_ID},
};

pub fn canonical_report(
    repository_id: &str,
    execution: &ExecutionReport,
) -> Result<ReportV1, AuditError> {
    let mut finding_ids = BTreeSet::new();
    let mut findings = Vec::new();
    let mut gaps = execution.gaps.clone();
    let mut semantic_review = serde_json::Map::new();
    let mut change_risk = Value::Null;
    let mut advisory_ids: BTreeSet<String> = BTreeSet::new();
    let mut coverage_notes = execution.coverage_notes.clone();
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
        if !provider.result.applicable
            && provider
                .result
                .details
                .get("notApplicableReason")
                .and_then(Value::as_str)
                == Some("host-declaration-absent")
        {
            // Absence of a host declaration is a typed degradation note, never
            // a silent not-applicable and never a blocking gap.
            coverage_notes.push(if provider.provider == OWNERSHIP_PROVIDER_ID {
                "ownership-scan-unavailable:AUDIT_OWNERSHIP_SCAN_CMD unset".to_owned()
            } else {
                format!("host-declaration-absent:{}", provider.provider)
            });
        }
        if provider.provider == OWNERSHIP_PROVIDER_ID && !provider.result.required {
            // Advisory provider: degradation is a coverage note, not a gap.
            coverage_notes.extend(
                provider
                    .result
                    .degradation
                    .iter()
                    .map(|gap| format!("ownership-scan-degraded:{gap}")),
            );
        } else {
            gaps.extend(
                provider
                    .result
                    .degradation
                    .iter()
                    .map(|gap| format!("provider-degradation:{}:{gap}", provider.provider)),
            );
        }
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
            if provider.provider == OWNERSHIP_PROVIDER_ID && !provider.result.required {
                advisory_ids.insert(finding.id.to_string());
            }
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
    coverage_notes.sort();
    coverage_notes.dedup();
    let advisory_findings: Vec<Value> = findings
        .iter()
        .filter(|finding| advisory_ids.contains(finding.id.as_str()))
        .map(|finding| {
            json!({
                "id": finding.id.as_str(),
                "provider": finding.provider,
                "severity": finding.severity,
                "message": finding.message,
                "locations": finding.locations,
                "evidence": finding.evidence,
            })
        })
        .collect();
    let blocking_findings = findings
        .iter()
        .filter(|finding| !advisory_ids.contains(finding.id.as_str()))
        .count();
    let status = if !gaps.is_empty() {
        ReportStatus::Incomplete
    } else if blocking_findings == 0 {
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
            ("coverageNotes".into(), json!(coverage_notes)),
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
            ("advisoryFindings".into(), Value::Array(advisory_findings)),
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
            coverage_notes: Vec::new(),
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

    fn ownership_with_finding(required: bool) -> ProviderExecution {
        let mut row = provider(
            "governance.capability-ownership",
            json!({
                "findingMessages": {"governance.capability-ownership:audio.cargo.hound": "audio duplicates RightKit owner rightkit-audio"}
            }),
        );
        row.result.required = required;
        row.result.findings.push(FindingRef {
            id: FindingId::new("governance.capability-ownership:audio.cargo.hound").unwrap(),
            severity: "warning".into(),
        });
        row
    }

    #[test]
    fn ownership_findings_are_advisory_and_listed() {
        let report = canonical_report("fixture", &execution(vec![ownership_with_finding(false)]))
            .unwrap();
        assert_eq!(report.status, ReportStatus::Clean);
        assert_eq!(report.findings.len(), 1);
        let advisory = report.extensions["advisoryFindings"].as_array().unwrap();
        assert_eq!(advisory.len(), 1);
        assert_eq!(
            advisory[0]["id"],
            "governance.capability-ownership:audio.cargo.hound"
        );
    }

    #[test]
    fn required_ownership_findings_block_clean() {
        let report =
            canonical_report("fixture", &execution(vec![ownership_with_finding(true)])).unwrap();
        assert_eq!(report.status, ReportStatus::Findings);
        assert!(report.extensions["advisoryFindings"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unset_ownership_command_is_a_non_blocking_degradation_note() {
        let mut row = provider(
            "governance.capability-ownership",
            json!({"notApplicable": true, "notApplicableReason": "host-declaration-absent"}),
        );
        row.result.applicable = false;
        row.result.required = false;
        let report = canonical_report("fixture", &execution(vec![row])).unwrap();
        assert_eq!(report.status, ReportStatus::Clean);
        assert!(report.gaps.is_empty());
        assert!(report.claims["coverageNotes"]
            .as_array()
            .unwrap()
            .contains(&json!(
                "ownership-scan-unavailable:AUDIT_OWNERSHIP_SCAN_CMD unset"
            )));
    }
}
