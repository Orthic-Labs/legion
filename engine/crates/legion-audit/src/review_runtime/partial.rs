//! Retain paid author claims when independent verification/ingest cannot finish.
//! These projections grant no receipt, delivery, source or verification credit.
use super::{digest_bytes, invalid, native, persist, read_json, Observation};
use crate::{
    error::AuditError,
    native_providers::reasoning::{ingest, PendingLensWork, ReasoningInvocation},
};
use legion_contracts::{Finding, FindingId, ReportStatus};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};

pub(super) fn preserve_author(
    run: &Path,
    work: &PendingLensWork,
    raw: &Value,
    author: &Observation,
) -> Result<(), AuditError> {
    preserve_request(run, &work.request, raw, author)
}
pub(super) fn preserve_request(
    run: &Path,
    request: &ReasoningInvocation,
    raw: &Value,
    author: &Observation,
) -> Result<(), AuditError> {
    let name = format!(
        "{}.json",
        digest_bytes(request.request_id.as_bytes()).trim_start_matches("sha256:")
    );
    let part = request.packet.get("part").filter(|part| !part.is_null());
    let packet_file = match part.and_then(|part| part["number"].as_u64()) {
        Some(number) => format!("{}.part-{number:04}.json", request.provider_id),
        None => format!("{}.json", request.provider_id),
    };
    persist(
        &run.join("runtime-author-results"),
        &name,
        &json!({"schemaVersion":1,"provider":request.provider_id,"requestId":request.request_id,"packetDigest":super::digest(&request.packet)?,"packetFile":packet_file,"part":part,"result":raw,"author":native::observation_value(author)}),
    )?;
    Ok(())
}

fn mark_incomplete(recomputed: &mut ingest::Recomputed, gap: String) {
    if !recomputed.report.gaps.contains(&gap) {
        recomputed.report.gaps.push(gap);
    }
    recomputed.report.gaps.sort();
    recomputed.report.status = ReportStatus::Incomplete;
    for field in ["auditStatus", "qualityGate"] {
        recomputed
            .report
            .claims
            .insert(field.into(), json!("incomplete"));
    }
    recomputed
        .report
        .claims
        .insert("planComplete".into(), json!(false));
}

/// Keep terminal transport/budget failures visible even if every provider
/// receipt was written before the final failed operation.
pub fn project_runtime_state(recomputed: &mut ingest::Recomputed, runtime: &Value) {
    let dispatch_done = runtime["dispatchStatus"] == "done";
    let failures = runtime
        .get("failures")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    let snapshot_gaps = runtime
        .get("snapshotGaps")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    let terminal_status = !matches!(
        runtime["status"].as_str(),
        Some("done" | "incomplete:required-evidence")
    );
    if !dispatch_done || failures || snapshot_gaps || terminal_status {
        let status = runtime["status"]
            .as_str()
            .unwrap_or("incomplete:reviewer-runtime");
        mark_incomplete(recomputed, format!("review-runtime-terminal:{status}"));
        recomputed
            .report
            .claims
            .insert("reviewRuntimeTerminal".into(), runtime.clone());
    }
}

pub fn recompute_with_partial_results(run: &Path) -> Result<ingest::Recomputed, AuditError> {
    let mut recomputed = ingest::recompute_run(run)?;
    let dir = run.join("runtime-author-results");
    if !dir.exists() {
        return Ok(recomputed);
    }
    let mut artifacts = fs::read_dir(dir)
        .map_err(|error| invalid(error.to_string()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| invalid(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if artifacts.len() > 4096 {
        return Err(invalid("partial author artifact count exceeds bound"));
    }
    artifacts.sort();
    let mut claims = Vec::new();
    for path in artifacts {
        let artifact = read_json(&path)?;
        let provider = artifact["provider"]
            .as_str()
            .ok_or_else(|| invalid("partial author provider missing"))?
            .to_owned();
        let number = artifact.pointer("/part/number").and_then(Value::as_u64);
        let accepted = if let Some(number) = number {
            recomputed
                .lens_parts
                .get(&provider)
                .is_some_and(|parts| parts.ingested.contains(&(number as u32)))
        } else {
            recomputed.ingested.iter().any(|id| id == &provider)
        };
        // Authenticated ingestion supersedes the original, including verified
        // withdrawals. Never resurrect a finding removed by its reviewer.
        if accepted {
            continue;
        }
        let packet_name = artifact["packetFile"]
            .as_str()
            .ok_or_else(|| invalid("partial packet filename missing"))?;
        if packet_name.contains('/') || packet_name.contains('\\') {
            return Err(invalid("unsafe partial packet filename"));
        }
        let packet = read_json(&run.join(ingest::LENS_PACKET_DIR).join(packet_name))?;
        let work: PendingLensWork =
            serde_json::from_value(packet).map_err(|error| invalid(error.to_string()))?;
        if work.provider_id != provider
            || artifact["requestId"] != work.request.request_id
            || artifact["packetDigest"] != super::digest(&work.request.packet)?
        {
            return Err(invalid("partial author packet binding mismatch"));
        }
        if let Some(findings) = artifact
            .pointer("/result/findings")
            .and_then(Value::as_array)
        {
            for raw in findings {
                let Some(id) = raw["id"].as_str().and_then(|id| FindingId::new(id).ok()) else {
                    continue;
                };
                if recomputed
                    .report
                    .findings
                    .iter()
                    .any(|finding| finding.id == id)
                {
                    continue;
                }
                let mut evidence = BTreeMap::new();
                evidence.insert("verifyStatus".into(), json!("unverified"));
                evidence.insert(
                    "runtimeState".into(),
                    json!("author-result-awaiting-independent-verification-or-ingest"),
                );
                evidence.insert("authorClaim".into(), raw.clone());
                evidence.insert("sourceAnchorVerified".into(), json!(false));
                recomputed.report.findings.push(Finding {
                    id,
                    provider: Some(provider.clone()),
                    severity: raw["severity"].as_str().unwrap_or("info").into(),
                    title: raw["title"]
                        .as_str()
                        .unwrap_or("Unverified author finding")
                        .into(),
                    message: raw["failureScenario"]
                        .as_str()
                        .unwrap_or("Author claim retained pending independent verification")
                        .into(),
                    locations: Vec::new(),
                    evidence,
                });
            }
        }
        claims.push(artifact);
        mark_incomplete(
            &mut recomputed,
            format!(
                "runtime-author-result-unverified:{provider}:{}",
                work.request.request_id
            ),
        );
    }
    recomputed
        .report
        .findings
        .sort_by(|left, right| left.id.cmp(&right.id));
    if !claims.is_empty() {
        recomputed
            .report
            .claims
            .insert("unverifiedAuthorResults".into(), json!(claims));
    }
    Ok(recomputed)
}
