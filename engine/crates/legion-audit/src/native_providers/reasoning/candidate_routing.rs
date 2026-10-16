//! Lossless scanner-to-lens routing. Routing is context, never a verdict.

use std::collections::BTreeSet;

use legion_contracts::{canonical_digest, ProviderResult};
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

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(domain: &str, id: &str) -> ScannerCandidate {
        ScannerCandidate {
            finding_id: id.into(),
            provider: "mixed-generator".into(),
            domain: domain.into(),
            path: Some("src/app.rs".into()),
            evidence_digest: format!("evidence-{id}"),
            ..Default::default()
        }
    }

    #[test]
    fn mixed_domains_route_once_without_security_reinterpretation() {
        let domains = [
            "security",
            "data",
            "reliability",
            "release",
            "architecture",
            "documentation",
            "quality",
            "schema",
            "unknown-new-domain",
        ];
        let candidates = domains
            .iter()
            .enumerate()
            .map(|(i, domain)| candidate(domain, &i.to_string()))
            .collect::<Vec<_>>();
        let security = routed_candidates(ADJUDICATOR_PROVIDER_ID, &candidates);
        assert_eq!(security, vec![candidates[0].clone()]);
        let mut accounted = Vec::new();
        for provider in [
            ADJUDICATOR_PROVIDER_ID,
            "reasoning.data-safety",
            "reasoning.resilience",
            "reasoning.release-readiness",
            "reasoning.architecture",
            "reasoning.doc-drift",
            "reasoning.ai-slop",
            "reasoning.schema",
        ] {
            accounted.extend(
                routed_candidates(provider, &candidates)
                    .into_iter()
                    .map(|candidate| candidate.finding_id),
            );
        }
        assert_eq!(accounted.len(), 8);
        assert_eq!(accounted.iter().collect::<BTreeSet<_>>().len(), 8);
        assert!(target_provider(&candidates[8]).is_none());
    }

    #[test]
    fn framework_rules_keep_security_schema_architecture_and_reliability_separate() {
        for (rule, domain) in [
            ("next-public-secret", "security"),
            ("nuxt-ssr-disabled", "architecture"),
            ("fastify-schema-missing", "schema"),
            ("go-http-no-timeouts", "reliability"),
            ("future-rule", "unknown"),
        ] {
            assert_eq!(
                super::super::security_adjudication::candidate_domain(
                    "legacy.framework.major-suite",
                    rule
                ),
                domain
            );
        }
    }

    #[test]
    fn unavailable_run_accounting_is_complete_without_repeating_evidence_in_packets() {
        let candidates = (0..256)
            .map(|index| {
                let mut candidate = candidate("security", &format!("nomination-{index}"));
                candidate.evidence_excerpt =
                    Some(format!("source evidence {index}: {}", "x".repeat(4096)));
                candidate
            })
            .collect::<Vec<_>>();
        let accounting = accounting_for_providers(&[], &candidates);
        let archived = serde_json::to_vec(&accounting).unwrap();
        assert!(archived.len() > 1_000_000);
        assert_eq!(accounting["candidateCount"], 256);
        let gaps = unavailable_gaps(&accounting);
        assert_eq!(gaps.len(), candidates.len());
        assert_eq!(gaps.iter().collect::<BTreeSet<_>>().len(), candidates.len());
        for (row, candidate) in accounting["routes"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&candidates)
        {
            assert_eq!(row["candidateId"], candidate.finding_id);
            assert_eq!(row["candidate"], json!(candidate));
            assert!(gaps.contains(&format!(
                "candidate-route-unavailable:{}:{}",
                candidate.provider, candidate.finding_id
            )));
        }
        let reference = packet_reference(&accounting).unwrap();
        assert!(serde_json::to_vec(&reference).unwrap().len() < 512);
        assert!(reference.get("routes").is_none());
        assert_eq!(reference["snapshotRef"], ROUTING_SNAPSHOT_FILE);
        assert_eq!(
            reference["accountingDigest"],
            canonical_digest(&accounting).unwrap()
        );
        assert_eq!(reference["unavailableCount"], candidates.len());
        assert_eq!(reference["disposition"], "none-implied");

        // Changing any archived evidence changes this packet binding.
        let mut changed = accounting.clone();
        changed["routes"][0]["candidate"]["evidenceExcerpt"] = json!("different source evidence");
        assert_ne!(
            packet_reference(&changed).unwrap()["accountingDigest"],
            reference["accountingDigest"]
        );

        // Source promotion into an unrelated lens does not transfer semantic
        // ownership of unavailable security review; the run retains its gaps.
        let mut request = request(&[]);
        request.provider_id = "reasoning.performance".into();
        request.packet["candidateRouting"] = reference;
        assert!(super::super::required_packet_gaps(&request).is_empty());
        assert_eq!(unavailable_gaps(&accounting), gaps);
    }

    #[test]
    fn candidate_context_is_not_duplicated_across_continuation_parts_or_lost_outside_sample() {
        let mut candidates = vec![
            candidate("quality", "included"),
            candidate("quality", "unsampled"),
            candidate("quality", "unanchored"),
        ];
        candidates[1].path = Some("src/unsampled.rs".into());
        candidates[2].path = None;
        let parts = vec![
            vec!["src/other.rs".into()],
            vec!["src/app.rs".into()],
            vec!["src/app.rs".into()],
        ];
        let assigned = (0..parts.len())
            .flat_map(|index| candidates_for_part(&candidates, &parts, index))
            .collect::<Vec<_>>();
        assert_eq!(assigned.len(), candidates.len());
        assert_eq!(candidates_for_part(&candidates, &parts, 0).len(), 2);
        assert_eq!(candidates_for_part(&candidates, &parts, 1).len(), 1);
        assert!(candidates_for_part(&candidates, &parts, 2).is_empty());
    }

    fn request(candidates: &[ScannerCandidate]) -> ReasoningInvocation {
        ReasoningInvocation {
            schema_version: 1,
            kind: super::super::REASONING_INVOCATION_KIND.into(),
            request_id: "request".into(),
            provider_id: "reasoning.ai-slop".into(),
            contract: "audit-lens-ai-slop-v1".into(),
            plan_digest: "plan".into(),
            plan_signature: "signature".into(),
            repository_id: "repo".into(),
            inventory_generation: "generation".into(),
            inventory_digest: "inventory".into(),
            denominator_digest: "denominator".into(),
            denominator_count: 1,
            denominator_paths: vec!["src/app.rs".into()],
            packet: json!({"candidateContext": candidates}),
        }
    }

    fn result() -> ProviderResult {
        ProviderResult {
            schema_version: 1,
            provider: legion_contracts::ProviderId::new("reasoning.ai-slop").unwrap(),
            applicable: true,
            required: true,
            status: legion_contracts::ProviderStatus::Partial,
            complete: false,
            coverage: None,
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: Default::default(),
        }
    }

    #[test]
    fn adapter_category_and_frozen_applicability_survive_broad_security_provider() {
        let provider = AuditProvider {
            id: "security.mixed".into(),
            version: "1".into(),
            role: "candidate-generator".into(),
            phase: "source".into(),
            lens_ids: vec!["security".into()],
            dependencies: Vec::new(),
            kind: ProviderKind::RustAlgorithm,
            configuration: [
                ("family".into(), json!("security")),
                ("denominatorCount".into(), json!(7)),
            ]
            .into(),
            bounds: Default::default(),
            clean_claim: "candidate-only".into(),
            benchmark_status: "qualified".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: true,
        };
        let mut candidate = candidate("security", "style-warning");
        candidate.source_mapping =
            json!({"category":"quality", "adapterEvidence":{"ruleId":"style"}});
        bind_generator(&mut candidate, &provider, &result());
        assert_eq!(candidate.domain, "quality");
        assert_eq!(candidate.source_mapping["category"], "quality");
        assert_eq!(
            candidate.source_mapping["frozenGenerator"]["denominatorCount"],
            7
        );
        assert_eq!(
            candidate.source_mapping["frozenGenerator"]["resultApplicable"],
            true
        );
        assert_eq!(
            target_provider(&candidate).as_deref(),
            Some("reasoning.ai-slop")
        );
        assert!(routed_candidates(ADJUDICATOR_PROVIDER_ID, &[candidate]).is_empty());
    }

    #[test]
    fn absent_unresolved_or_unbound_dispositions_never_erase_candidates() {
        let candidates = vec![candidate("quality", "candidate-1")];
        let request = request(&candidates);
        let mut result = result();
        assert_eq!(
            pending_review_gaps(&request, &result).unwrap(),
            ["candidate-review-pending:mixed-generator:candidate-1"]
        );
        let disposition = json!({"candidateId":"candidate-1", "provider":"mixed-generator", "evidenceDigest":"evidence-candidate-1", "status":"unresolved", "reason":"needs source evidence"});
        result
            .details
            .insert("candidateDispositions".into(), json!([disposition]));
        assert_eq!(pending_review_gaps(&request, &result).unwrap().len(), 1);
        result.details.get_mut("candidateDispositions").unwrap()[0]["status"] = json!("dismissed");
        assert!(pending_review_gaps(&request, &result).is_err());
        result.details.get_mut("candidateDispositions").unwrap()[0]["evidence"] =
            json!(["src/app.rs:12"]);
        assert!(pending_review_gaps(&request, &result).unwrap().is_empty());
        result.details.get_mut("candidateDispositions").unwrap()[0]["evidenceDigest"] =
            json!("wrong-evidence");
        assert!(pending_review_gaps(&request, &result).is_err());
    }
}
