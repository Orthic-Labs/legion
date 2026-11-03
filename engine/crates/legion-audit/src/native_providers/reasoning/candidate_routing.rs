//! Lossless scanner-to-lens routing. Routing is context, never a verdict.

use std::collections::BTreeSet;

use rightkit_evidence_contracts::{canonical_digest, ProviderResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{ReasoningInvocation, ScannerCandidate, ADJUDICATOR_PROVIDER_ID};
use crate::plan::{AuditProvider, FrozenPlan, ProviderKind};

/// Complete run-level routing ledger. Reviewer packets carry its digest &
/// reference, while actionable candidate evidence stays in its owning lens.
pub const ROUTING_SNAPSHOT_FILE: &str = "candidate-routing.json";

/// Adapter categories outrank broad provider families. Frozen generator facts
/// remain alongside original mapping; an unfamiliar category stays unresolved.
pub fn bind_generator(
    candidate: &mut ScannerCandidate,
    provider: &AuditProvider,
    result: &ProviderResult,
) {
    let explicit_domain = [
        "/domain",
        "/category",
        "/adapterEvidence/domain",
        "/adapterEvidence/category",
    ]
    .into_iter()
    .find_map(|pointer| {
        candidate
            .source_mapping
            .pointer(pointer)
            .and_then(Value::as_str)
    })
    .filter(|domain| !domain.trim().is_empty())
    .map(str::to_owned);
    if let Some(domain) = explicit_domain {
        candidate.domain = domain;
    } else if candidate.domain.is_empty() || candidate.domain == "unknown" {
        // Framework is deliberately excluded: its rules mix vulnerability,
        // configuration, schema & reliability claims.
        let family = provider.configuration.get("family").and_then(Value::as_str);
        if let Some(family) =
            family.filter(|family| *family != "framework" && target_lens(family).is_some())
        {
            candidate.domain = family.into();
        } else if provider.lens_ids.len() == 1 && provider.lens_ids[0] == "security" {
            candidate.domain = "security".into();
        }
    }
    candidate.source_mapping["frozenGenerator"] = json!({
        "providerId": provider.id,
        "family": provider.configuration.get("family"),
        "lensIds": provider.lens_ids,
        "selector": provider.configuration.get("selector"),
        "denominatorDigest": provider.configuration.get("denominatorDigest"),
        "denominatorCount": provider.configuration.get("denominatorCount"),
        "providerApplicable": !provider.not_applicable(),
        "resultApplicable": result.applicable,
        "resultStatus": result.status,
        "authority": "frozen-plan",
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateRoute {
    Security,
    Lens,
    Unavailable,
}

pub fn target_lens(domain: &str) -> Option<&'static str> {
    Some(match domain {
        "security" => "security",
        "data" | "data-safety" => "data-safety",
        "reliability" | "resilience" => "resilience",
        "release" | "release-readiness" => "release-readiness",
        "architecture" => "architecture",
        "documentation" | "docs" | "doc-drift" => "doc-drift",
        "quality" | "ai-slop" => "ai-slop",
        "correctness" | "framework" => "correctness",
        "schema" => "schema",
        "performance" => "performance",
        "a11y" | "accessibility" => "a11y",
        "platform-parity" => "platform-parity",
        "naming" => "naming",
        "dead-file" => "dead-file",
        "minimize" => "minimize",
        _ => return None,
    })
}

pub fn target_provider(candidate: &ScannerCandidate) -> Option<String> {
    let domain = super::security_adjudication::effective_candidate_domain(candidate);
    let lens = target_lens(domain)?;
    Some(if lens == "security" {
        ADJUDICATOR_PROVIDER_ID.into()
    } else {
        format!("reasoning.{lens}")
    })
}

pub fn routed_candidates(provider: &str, candidates: &[ScannerCandidate]) -> Vec<ScannerCandidate> {
    candidates
        .iter()
        .filter(|candidate| target_provider(candidate).as_deref() == Some(provider))
        .cloned()
        .collect()
}

/// Validate before routing or partitioning so duplicate ownership cannot hide
/// in different lenses or physical continuations.
pub(super) fn validate_identities(candidates: &[ScannerCandidate]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if !seen.insert((&candidate.provider, &candidate.finding_id)) {
            return Err("duplicate routed candidate identity".into());
        }
    }
    Ok(())
}

/// Candidate continuations have no source-coverage authority. Require the
/// exact role, full typed records, owning lens & empty source-bearing arrays.
pub(super) fn is_candidate_part(request: &ReasoningInvocation) -> bool {
    let packet = &request.packet;
    if request.validate().is_err()
        || request.provider_id == ADJUDICATOR_PROVIDER_ID
        || packet.pointer("/part/kind").and_then(Value::as_str) != Some("candidate-context")
        || request
            .part()
            .is_none_or(|part| part.number == 0 || part.number > part.total)
        || packet
            .pointer("/excerptCoverage/basis")
            .and_then(Value::as_str)
            != Some("candidate-context")
        || [
            "/part/paths",
            "/part/continuedPaths",
            "/excerpts",
            "/excerptCoverage/selectedPaths",
            "/excerptCoverage/materializedPaths",
            "/excerptCoverage/examinedPaths",
            "/excerptCoverage/chunkedPaths",
            "/excerptCoverage/omittedPaths",
            "/excerptCoverage/truncatedPaths",
            "/excerptCoverage/aliasedPaths",
        ]
        .iter()
        .any(|pointer| packet.pointer(pointer) != Some(&json!([])))
    {
        return false;
    }
    if packet
        .pointer("/binding/denominatorDigest")
        .and_then(Value::as_str)
        != Some(request.denominator_digest.as_str())
        || packet
            .pointer("/binding/denominatorCount")
            .and_then(Value::as_u64)
            != Some(request.denominator_count)
        || packet
            .pointer("/binding/planDigest")
            .and_then(Value::as_str)
            != Some(request.plan_digest.as_str())
        || packet
            .pointer("/binding/inventoryDigest")
            .and_then(Value::as_str)
            != Some(request.inventory_digest.as_str())
    {
        return false;
    }
    let Some(context) = packet.get("candidateContext") else {
        return false;
    };
    let Ok(candidates) = serde_json::from_value::<Vec<ScannerCandidate>>(context.clone()) else {
        return false;
    };
    !candidates.is_empty()
        && json!(candidates) == *context
        && validate_identities(&candidates).is_ok()
        && candidates.iter().all(|candidate| {
            !candidate.provider.trim().is_empty()
                && !candidate.finding_id.trim().is_empty()
                && !candidate.evidence_digest.trim().is_empty()
                && target_provider(candidate).as_deref() == Some(request.provider_id.as_str())
        })
}

/// Serializer-derived minimum for returning one explicit disposition per
/// owned candidate. Evidence/reason content still consumes the fitting cap.
pub(super) fn disposition_output_tokens(request: &ReasoningInvocation) -> u64 {
    let rows = request
        .packet
        .get("candidateContext")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|candidate| {
            json!({
                "candidateId": candidate["findingId"],
                "provider": candidate["provider"],
                "evidenceDigest": candidate["evidenceDigest"],
                "status": "unresolved", "reason": "pending", "evidence": [],
            })
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return 0;
    }
    let bytes = serde_json::to_vec(&json!({"finalResult": {
        "complete": true, "findings": [], "withdrawn": [], "candidateDispositions": rows,
    }}))
    .map_or(u64::MAX, |bytes| bytes.len() as u64);
    crate::next::estimated_request_tokens(bytes, 0)
}

/// A candidate belongs to its first materialized path part. Unmaterialized or
/// unknown anchors stay in part one, where they require an explicit gap.
pub fn candidates_for_part(
    candidates: &[ScannerCandidate],
    part_paths: &[Vec<String>],
    index: usize,
) -> Vec<ScannerCandidate> {
    candidates
        .iter()
        .filter(|candidate| {
            candidate
                .path
                .as_ref()
                .and_then(|path| part_paths.iter().position(|paths| paths.contains(path)))
                .unwrap_or(0)
                == index
        })
        .cloned()
        .collect()
}

/// Frozen plan decides whether a lane exists & applies. Unsupported categories
/// remain visible, including full candidate evidence in the accounting packet.
pub fn accounting(plan: &FrozenPlan, candidates: &[ScannerCandidate]) -> Value {
    accounting_for_providers(plan.providers(), candidates)
}

fn accounting_for_providers(providers: &[AuditProvider], candidates: &[ScannerCandidate]) -> Value {
    let routes = candidates
        .iter()
        .map(|candidate| {
            let target = target_provider(candidate);
            let active = target.as_ref().is_some_and(|target| {
                providers.iter().any(|provider| {
                    provider.id == *target
                        && provider.kind == ProviderKind::HostService
                        && !provider.not_applicable()
                })
            });
            let route = if !active {
                CandidateRoute::Unavailable
            } else if target.as_deref() == Some(ADJUDICATOR_PROVIDER_ID) {
                CandidateRoute::Security
            } else {
                CandidateRoute::Lens
            };
            let lens = target_lens(super::security_adjudication::effective_candidate_domain(
                candidate,
            ));
            json!({
                "candidateId": candidate.finding_id,
                "provider": candidate.provider,
                "domain": candidate.domain,
                "evidenceDigest": candidate.evidence_digest,
                "targetProvider": target,
                "targetLens": lens,
                "route": route,
                "status": if active { "pending-review" } else { "domain-review-unavailable" },
                "reportSchema": lens.map(|lens| format!("audit.lens.{lens}.v1")),
                "candidate": if active { Value::Null } else { json!(candidate) },
            })
        })
        .collect::<Vec<_>>();
    json!({"schemaVersion": 1, "candidateCount": candidates.len(), "routes": routes})
}

/// A routing ledger is run accounting, not reviewer input. Repeating its full
/// unavailable evidence in unrelated packets spends their physical budget &
/// incorrectly makes those lenses own missing review lanes. The run retains
/// every unavailable gap; this reference cannot dispose of any candidate.
pub fn packet_accounting(
    plan: &FrozenPlan,
    candidates: &[ScannerCandidate],
) -> Result<Value, String> {
    packet_reference(&accounting(plan, candidates))
}

fn packet_reference(accounting: &Value) -> Result<Value, String> {
    Ok(json!({
        "schemaVersion": 1,
        "kind": "candidate-routing-reference",
        "snapshotRef": ROUTING_SNAPSHOT_FILE,
        "accountingDigest": canonical_digest(accounting).map_err(|error| error.to_string())?,
        "candidateCount": accounting["candidateCount"],
        "unavailableCount": unavailable_gaps(accounting).len(),
        "scope": "run-accounting-only",
        "disposition": "none-implied",
    }))
}

/// Run-level unresolved routes remain independent of any lens's findings or
/// source-promotion status, including when no reasoning lane is selected.
pub fn unavailable_gaps(accounting: &Value) -> Vec<String> {
    accounting["routes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|route| route["route"].as_str() == Some("unavailable"))
        .map(|route| {
            format!(
                "candidate-route-unavailable:{}:{}",
                route["provider"].as_str().unwrap_or("unknown"),
                route["candidateId"].as_str().unwrap_or("unknown")
            )
        })
        .collect()
}

pub fn accounting_owner(plan: &FrozenPlan) -> Option<&str> {
    let active = || {
        plan.providers().iter().filter(|provider| {
            provider.kind == ProviderKind::HostService
                && super::REASONING_PROVIDER_IDS.contains(&provider.id.as_str())
                && !provider.not_applicable()
        })
    };
    active()
        .find(|provider| provider.id == ADJUDICATOR_PROVIDER_ID)
        .or_else(|| active().next())
        .map(|provider| provider.id.as_str())
}

fn pending_gap(candidate: &ScannerCandidate) -> String {
    format!(
        "candidate-review-pending:{}:{}",
        candidate.provider, candidate.finding_id
    )
}

/// Signed findings do not implicitly dispose of scanner context. Each candidate
/// needs an explicit, evidence-bound disposition, or an unresolved coverage gap.
pub fn pending_review_gaps(
    request: &ReasoningInvocation,
    result: &ProviderResult,
) -> Result<Vec<String>, String> {
    let Some(context) = request
        .packet
        .get("candidateContext")
        .filter(|value| !value.is_null())
    else {
        return Ok(Vec::new());
    };
    let candidates: Vec<ScannerCandidate> = serde_json::from_value(context.clone())
        .map_err(|error| format!("candidate context malformed: {error}"))?;
    let mut identities = BTreeSet::new();
    for candidate in &candidates {
        if !identities.insert((&candidate.provider, &candidate.finding_id)) {
            return Err("duplicate routed candidate identity".into());
        }
    }
    let dispositions = match result.details.get("candidateDispositions") {
        None => &[][..],
        Some(value) => value
            .as_array()
            .ok_or("candidateDispositions must be an array")?
            .as_slice(),
    };
    let mut seen = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    for row in dispositions {
        let id = row
            .get("candidateId")
            .and_then(Value::as_str)
            .ok_or("candidate disposition missing candidateId")?;
        let provider = row
            .get("provider")
            .and_then(Value::as_str)
            .ok_or("candidate disposition missing provider")?;
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.finding_id == id && candidate.provider == provider)
            .ok_or("candidate disposition outside routed context")?;
        if !seen.insert((provider, id)) {
            return Err("duplicate candidate disposition".into());
        }
        if row.get("evidenceDigest").and_then(Value::as_str)
            != Some(candidate.evidence_digest.as_str())
            || row
                .get("reason")
                .and_then(Value::as_str)
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err("candidate disposition lacks bound evidence or reason".into());
        }
        match row.get("status").and_then(Value::as_str) {
            Some("unresolved") => continue,
            Some("confirmed" | "dismissed") => {}
            _ => return Err("unsupported candidate disposition status".into()),
        }
        let anchored = row
            .get("evidence")
            .and_then(Value::as_array)
            .is_some_and(|evidence| {
                evidence.iter().filter_map(Value::as_str).any(|location| {
                    location.rsplit_once(':').is_some_and(|(path, range)| {
                        candidate.path.as_deref() == Some(path)
                            && range
                                .split('-')
                                .all(|line| line.parse::<u64>().is_ok_and(|line| line > 0))
                    })
                })
            });
        if !anchored {
            return Err("resolved candidate disposition needs candidate-file evidence".into());
        }
        if row.get("status").and_then(Value::as_str) == Some("confirmed") {
            let finding = row
                .get("findingId")
                .and_then(Value::as_str)
                .ok_or("confirmed candidate missing findingId")?;
            if !result
                .findings
                .iter()
                .any(|entry| entry.id.as_str() == finding)
                || !result
                    .details
                    .get("lensFindings")
                    .and_then(Value::as_array)
                    .is_some_and(|findings| {
                        findings
                            .iter()
                            .any(|entry| entry.get("id").and_then(Value::as_str) == Some(finding))
                    })
            {
                return Err("confirmed candidate is absent from lens findings".into());
            }
        }
        resolved.insert((provider, id));
    }
    Ok(candidates
        .iter()
        .filter(|candidate| {
            !resolved.contains(&(candidate.provider.as_str(), candidate.finding_id.as_str()))
        })
        .map(pending_gap)
        .collect())
}
