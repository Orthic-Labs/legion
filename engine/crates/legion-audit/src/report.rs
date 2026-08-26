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
    for provider in &execution.results {
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
            let evidence = detail_object(&provider.result.details, "findingEvidence", &finding.id);
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
            ("lensesRan".into(), json!(execution.lenses_ran)),
        ]),
        targets: vec![repository_id.to_owned()],
        extensions: BTreeMap::from([(
            "providerResults".into(),
            serde_json::to_value(&execution.results)
                .map_err(|error| AuditError::Invalid(error.to_string()))?,
        )]),
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
