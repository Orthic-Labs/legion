//! Production route for the five heuristic security packs.
//!
//! `security.credentials`, `security.insecure-defaults`,
//! `security.misuse-resistance`, `security.agentic-ci` and
//! `security.agent-skill-mcp` are candidate generators: they read the provider's
//! frozen selector paths and raise `details.candidates` for the adjudicator.
//! They never emit findings and never adjudicate (`validate_result` rejects a
//! candidate generator that does). Coverage is bound to the frozen
//! denominator (digest and count); `examined` counts only files actually read,
//! and every file the bounded reader could not examine is a named gap.
//!
//! The detectors live in `p11d_quality::security_suite`; this module owns the
//! provider contract around them.

use std::path::Path;

use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};
use serde_json::{json, Value};

use crate::{
    error::AuditError,
    native_providers::{
        availability,
        p11d_quality::security_suite::{self, Limits},
    },
    plan::AuditProvider,
};

use super::common::digest;

/// (registered provider id, pack name) for every heuristic pack.
pub const PACK_PROVIDERS: [(&str, &str); 5] = [
    ("security.credentials", "credentials"),
    ("security.insecure-defaults", "insecure-defaults"),
    ("security.misuse-resistance", "misuse-resistance"),
    ("security.agentic-ci", "agentic-ci"),
    ("security.agent-skill-mcp", "agent-skill-mcp"),
];

/// The pack a provider id runs, if it is one of the five.
pub fn pack_for(provider_id: &str) -> Option<&'static str> {
    PACK_PROVIDERS
        .iter()
        .find(|(id, _)| *id == provider_id)
        .map(|(_, pack)| *pack)
}

fn gap_strings(gaps: &[Value]) -> Vec<String> {
    gaps.iter()
        .map(|gap| serde_json::to_string(gap).unwrap_or_else(|_| "coverage-gap".into()))
        .collect()
}

/// Runs `pack` for `provider`.
///
/// * `root`: the audited root (absent: the provider is unavailable).
/// * `frozen`: the frozen selector denominator as (digest, count).
/// * `paths`: the frozen selector denominator paths.
pub fn execute(
    provider: &AuditProvider,
    pack: &str,
    root: Option<&Path>,
    frozen: Option<(String, u64)>,
    paths: Option<Vec<String>>,
) -> Result<ProviderResult, AuditError> {
    let provider_id = ProviderId::new(provider.id.clone())?;
    let base = |applicable: bool, coverage: Option<Coverage>| ProviderResult {
        schema_version: 1,
        provider: provider_id.clone(),
        applicable,
        required: provider.required,
        status: ProviderStatus::Partial,
        complete: false,
        coverage,
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: Default::default(),
    };

    let (Some((denominator_digest, count)), Some(paths)) = (frozen, paths) else {
        // No resolvable frozen selector: coverage cannot be bound to a
        // denominator, so nothing is analysed.
        let mut result = base(true, None);
        availability::mark_unavailable(
            &mut result,
            &format!("frozen-denominator-unresolvable:{}", provider.id),
        );
        return Ok(result);
    };
    if count == 0 || paths.is_empty() {
        // The selector matches nothing in this repository: not applicable,
        // never complete, nothing examined.
        let mut result = base(false, None);
        result
            .details
            .insert("candidates".into(), Value::Array(Vec::new()));
        return Ok(result);
    }
    let Some(root) = root else {
        let mut result = base(
            true,
            Some(Coverage {
                denominator_digest,
                expected: count,
                examined: 0,
                gaps: Vec::new(),
            }),
        );
        availability::mark_unavailable(&mut result, &format!("root-not-supplied:{}", provider.id));
        return Ok(result);
    };

    let report = match security_suite::generate_security_candidates_bounded(
        root,
        &paths,
        pack,
        Some(&provider.id),
        &Limits::default(),
    ) {
        Ok(report) => report,
        Err(error) => {
            let mut result = base(
                true,
                Some(Coverage {
                    denominator_digest,
                    expected: count,
                    examined: 0,
                    gaps: Vec::new(),
                }),
            );
            result.status = ProviderStatus::Failed;
            let gap = serde_json::to_string(&json!({"kind": "pack-failed", "detail": error}))
                .unwrap_or_else(|_| "pack-failed".into());
            result.coverage_gaps.push(gap.clone());
            if let Some(coverage) = result.coverage.as_mut() {
                coverage.gaps.push(gap);
            }
            return Ok(result);
        }
    };

    let scanned: Vec<String> = report["coverage"]["scanned"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let gaps: Vec<Value> = report["coverageGaps"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let candidates: Vec<Value> = report["candidates"].as_array().cloned().unwrap_or_default();
    // Never more than the frozen count, and only files actually read.
    let examined = (scanned.len() as u64).min(count);
    let complete = gaps.is_empty() && examined == count;
    let gap_list = gap_strings(&gaps);

    let analysis = json!({
        "kind": "audit-security-pack",
        "pack": pack,
        "policyId": report["policyId"],
        "status": if !candidates.is_empty() { "candidates" } else if complete { "pass" } else { "unproven" },
        "complete": complete,
        "denominator": {"kind": "security-pack-files", "expected": count, "examined": examined},
        "candidateCount": candidates.len(),
        "rules": report["coverage"]["rules"],
        "limits": report["coverage"]["limits"],
        "bytesRead": report["coverage"]["bytesRead"],
        "examinedDigest": digest(scanned.join("\n").as_bytes()),
        "skipped": report["coverage"]["skipped"],
        "suppressed": report["suppressed"],
        "coverageGaps": gaps,
        "findings": [],
    });

    let mut result = base(
        true,
        Some(Coverage {
            denominator_digest,
            expected: count,
            examined,
            gaps: gap_list.clone(),
        }),
    );
    result.status = if complete {
        ProviderStatus::Complete
    } else {
        ProviderStatus::Partial
    };
    result.complete = complete;
    result.coverage_gaps = gap_list;
    result.details.insert("analysis".into(), analysis);
    result
        .details
        .insert("candidates".into(), Value::Array(candidates));
    result.details.insert(
        "producer".into(),
        json!({
            "mode": "native-heuristic-pack",
            "evidence": "native-heuristic",
            "pack": pack,
            "policyId": security_suite::POLICY_ID,
            "network": false,
        }),
    );
    Ok(result)
}
