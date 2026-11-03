use std::collections::{BTreeMap, BTreeSet};

use rightkit_evidence_contracts::{
    Finding, FindingId, LiftContext, ReportId, ReportScope, ReportStatus, ReportV1, ReportV2,
};
use serde_json::{json, Value};

use crate::{
    assurance::{
        evidence_from_execution, reconcile, AuditAssuranceV1, Completion, ObligationEvidence,
        ObligationId, ObligationStatus, Waiver, AUDIT_ASSURANCE_EXTENSION_KEY,
    },
    error::AuditError,
    execution::{ExecutionReport, OWNERSHIP_PROVIDER_ID},
    plan::FrozenPlan,
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
        if let Some(reason) =
            crate::native_providers::availability::unavailable_reason(&provider.result)
        {
            coverage_notes.push(format!("unavailable:{}:{reason}", provider.provider));
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
    let mut report = ReportV1 {
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
            ("executionPolicy".into(), execution.execution_policy.clone()),
            (
                "executionPolicyIdentity".into(),
                execution.execution_policy_identity.clone(),
            ),
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
    // P-pos (ADR-4): position every line anchor deterministically. A required
    // anchor that fails forces `incomplete` through a gap, so every consumer of
    // the v1 core (ingest recompute, verify) reaches the same verdict.
    if std::path::Path::new(repository_id).is_dir() {
        let v2 = lift_report_v2(
            &report,
            ReportScope {
                spec: "whole".into(),
                base_ref_oid: None,
                merge_base_oid: None,
                head: execution.generation.clone(),
                snapshot_key: None,
                index_schema_version: None,
            },
        )?;
        report.gaps = v2.gaps;
        report.status = v2.status;
    }
    // Finalization: stored prior findings missing from this run without valid
    // resolution evidence stay open and keep the report from completing.
    if std::path::Path::new(repository_id).is_dir() {
        crate::finding_history::apply_history_gate(
            std::path::Path::new(repository_id),
            &mut report,
        )?;
    }
    report.validate()?;
    Ok(report)
}

/// Project a reconciled `auditAssuranceV1` into a v1 report as an additive
/// extension (it flows unchanged into the lifted ReportV2). The report can
/// never claim more than the evidence: every non-examined obligation is
/// recorded as a gap, and a `clean` status is downgraded to `incomplete`
/// unless the assurance is complete. Obligation findings with a clean
/// report are contradictory and rejected. A zero-finding, complete
/// assurance stays `clean` (no quota).
pub fn project_assurance(
    report: &mut ReportV1,
    assurance: &AuditAssuranceV1,
) -> Result<(), AuditError> {
    if report
        .extensions
        .contains_key(AUDIT_ASSURANCE_EXTENSION_KEY)
    {
        return Err(AuditError::Invalid(format!(
            "report extension {AUDIT_ASSURANCE_EXTENSION_KEY} is reserved"
        )));
    }
    for obligation in &assurance.obligations {
        if matches!(
            obligation.status,
            ObligationStatus::Unmet | ObligationStatus::Deferred | ObligationStatus::Waived
        ) {
            let state = format!("{:?}", obligation.status).to_ascii_lowercase();
            report.gaps.push(format!(
                "assurance-{state}:{}:{}",
                obligation.id.target, obligation.id.concern
            ));
        }
    }
    report.gaps.sort();
    report.gaps.dedup();
    if assurance.summary.findings > 0 && report.status == ReportStatus::Clean {
        return Err(AuditError::Invalid(
            "assurance obligations carry findings but the report claims clean".into(),
        ));
    }
    if assurance.summary.completion != Completion::Complete && report.status == ReportStatus::Clean
    {
        report.status = ReportStatus::Incomplete;
    }
    report.extensions.insert(
        AUDIT_ASSURANCE_EXTENSION_KEY.to_owned(),
        assurance.to_value()?,
    );
    report.validate()?;
    Ok(())
}

/// `canonical_report` plus assurance projection. For a plan without a
/// frozen assurance bound (legacy profiles) this is exactly
/// `canonical_report`. Otherwise results are reconciled against the frozen
/// denominator: provider evidence derives from the signed-plan execution,
/// `imported` evidence and `waivers` are validated against frozen identities
/// and anything unmatched is ignored (and surfaced as a gap).
pub fn canonical_report_assured(
    repository_id: &str,
    plan: &FrozenPlan,
    execution: &ExecutionReport,
    imported: &[ObligationEvidence],
    waivers: &[(ObligationId, Waiver)],
    now_rfc3339_utc: &str,
) -> Result<ReportV1, AuditError> {
    let mut report = canonical_report(repository_id, execution)?;
    let Some(frozen) = plan.plan().assurance_binding()? else {
        return Ok(report);
    };
    let mut evidence = evidence_from_execution(&frozen, plan, execution);
    evidence.extend(imported.iter().cloned());
    let reconciled = reconcile(&frozen, &evidence, waivers, now_rfc3339_utc)?;
    for rejected in &reconciled.rejected {
        report.gaps.push(format!("assurance-rejected:{rejected}"));
    }
    project_assurance(&mut report, &reconciled.assurance)?;
    if !reconciled.rejected.is_empty() && report.status == ReportStatus::Clean {
        report.status = ReportStatus::Incomplete;
    }
    Ok(report)
}

/// Lifts a writer's v1 report into schema v2 (ADR-8): deterministic anchor
/// positioning against the repository root named by `targets[0]` (no model),
/// confidence classification and the ADR-4 status rules. When the root is not
/// a directory positioning is unavailable and no anchor is reported failed.
/// No provider declares `exactness: exact` yet, so an anchored tool hit is
/// `likely`, never `proven`.
pub fn lift_report_v2(report: &ReportV1, scope: ReportScope) -> Result<ReportV2, AuditError> {
    let root = report
        .targets
        .first()
        .map(std::path::PathBuf::from)
        .filter(|root| root.is_dir());
    let v2 = match &root {
        Some(root) => {
            let resolve = |relative: &str| -> Option<Vec<u8>> {
                let path = root.join(relative);
                let metadata = std::fs::symlink_metadata(&path).ok()?;
                if !metadata.is_file() {
                    return None;
                }
                std::fs::read(path).ok()
            };
            ReportV2::from_v1_with(report, &LiftContext::new(scope, &resolve))?
        }
        None => ReportV2::from_v1_with(report, &LiftContext::without_bytes(scope))?,
    };
    v2.validate()?;
    Ok(v2)
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
