//! Follow-up plan for security variant analysis.
//!
//! `legacy.security.variant-analysis` is selected by `confirmedSecurityFinding`,
//! which is empty when the parent plan is frozen: the confirmed findings only
//! exist after the adjudication lens is ingested. This module compiles and
//! freezes a SECOND plan, scoped to the variant-analysis provider, over the
//! files of the confirmed findings, and binds it to the parent run:
//!
//! * the follow-up plan carries `bounds.followup` = parent plan digest, the
//!   digest of the confirmed findings (their verdict digests) and the confirmed
//!   paths, so its digest and HMAC cover the binding;
//! * it lives in a self-contained run directory `<run>/followup/` (own
//!   `plan.json`, `frozen-plan.json`, `epoch.key`, `execution.json`,
//!   `report.json`, `lens-packets/`, `lens-receipts/`), so the ordinary
//!   `ingest_lens_result` / `recompute_run` machinery runs on it unchanged;
//! * the variant lens packet carries the confirmed findings as `variantSeeds`.
//!
//! `evaluate` is what the parent `recompute_run` consults: the
//! `security-variant-analysis-pending` gap clears only when the follow-up is
//! complete AND the whole chain verifies.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use legion_contracts::{canonical_digest, Finding};
use serde_json::{json, Value};

use super::{
    ingest::{
        create_epoch, expected_request_id, invalid, io, load_epoch, read_json, recompute_run,
        write_atomic, LENS_PACKET_DIR,
    },
    pending_lens_work,
    security_adjudication::{confirmed_paths, ConfirmedSecurityFinding, ADJUDICATOR_PROVIDER_ID},
    PendingLensWork, ReasoningProviderExecutor,
};
use crate::{
    error::AuditError,
    execution::{execute, ExecutionReport},
    inventory::{FilesystemInventorySource, InventorySource},
    plan::{AuditPlan, FOLLOWUP_BOUND},
    report::canonical_report,
};

/// Run-relative directory of the follow-up run.
pub const FOLLOWUP_DIR: &str = "followup";
/// File holding the complete frozen follow-up plan (plan.json only records its seal).
pub const FROZEN_PLAN_FILE: &str = "frozen-plan.json";
/// The provider the follow-up plan exists for.
pub const VARIANT_PROVIDER_ID: &str = "legacy.security.variant-analysis";

/// What `compile_followup` produced (or found already in place).
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowupPlanned {
    pub dir: PathBuf,
    pub plan_path: PathBuf,
    pub plan_digest: String,
    pub parent_plan_digest: String,
    pub confirmed_paths: Vec<String>,
    pub seeds: usize,
    pub provider: String,
    pub packet: PathBuf,
    pub packet_digest: String,
    /// The existing follow-up already matched the parent and was left untouched.
    pub reused: bool,
}

/// State of the follow-up as seen from the parent run.
#[derive(Clone, Debug)]
pub enum FollowupState {
    /// No follow-up has been compiled.
    Absent,
    /// Compiled and chain-verified, but the variant lens is not (fully) ingested.
    Pending(String),
    /// The follow-up exists but its chain does not verify against the parent.
    Invalid(String),
    /// Ingested, complete, and verified.
    Complete(FollowupDone),
}

#[derive(Clone, Debug)]
pub struct FollowupDone {
    pub plan_digest: String,
    pub parent_plan_digest: String,
    pub confirmed_paths: Vec<String>,
    pub findings: Vec<Finding>,
}

impl FollowupState {
    /// The `securityVariantFollowup` report claim.
    pub fn claim(&self) -> Value {
        match self {
            Self::Absent => json!({"status": "absent"}),
            Self::Pending(reason) => json!({"status": "pending", "reason": reason}),
            Self::Invalid(reason) => json!({"status": "invalid", "reason": reason}),
            Self::Complete(done) => json!({
                "status": "complete",
                "planDigest": done.plan_digest,
                "parentPlanDigest": done.parent_plan_digest,
                "confirmedPaths": done.confirmed_paths,
                "findings": done.findings.len(),
            }),
        }
    }
}

fn seal_digest(plan_json: &Value, who: &str) -> Result<String, AuditError> {
    plan_json
        .pointer("/seal/digest")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid(format!("{who} has no seal digest")))
}

/// Digest binding the follow-up to the exact confirmed verdicts (each carries
/// its verdict digest).
fn confirmed_digest(confirmed: &[ConfirmedSecurityFinding]) -> Result<String, AuditError> {
    canonical_digest(&json!(confirmed)).map_err(|error| invalid(error.to_string()))
}

/// Paths of the confirmed findings; every confirmed finding must be scoped to a
/// file, otherwise variant analysis cannot be bound to a denominator.
fn scoped_paths(confirmed: &[ConfirmedSecurityFinding]) -> Result<Vec<String>, AuditError> {
    if let Some(unscoped) = confirmed.iter().find(|finding| finding.path.is_none()) {
        return Err(invalid(format!(
            "confirmed finding {} carries no source path; variant analysis cannot be scoped to it",
            unscoped.candidate_id
        )));
    }
    let paths = confirmed_paths(confirmed);
    if paths.is_empty() {
        return Err(invalid("no confirmed security finding to analyse"));
    }
    Ok(paths)
}

/// One seed per confirmed finding: scanner rule/location plus the adjudicator's
/// reasoning, joined from the parent adjudication packet and receipt.
fn seeds(run_dir: &Path, confirmed: &[ConfirmedSecurityFinding]) -> Result<Vec<Value>, AuditError> {
    let packet = read_json(
        &run_dir
            .join(LENS_PACKET_DIR)
            .join(format!("{ADJUDICATOR_PROVIDER_ID}.json")),
    )?;
    let candidates = packet
        .pointer("/request/packet/scannerCandidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let receipt = read_json(
        &run_dir
            .join(super::ingest::LENS_RECEIPT_DIR)
            .join(format!("{ADJUDICATOR_PROVIDER_ID}.json")),
    )?;
    let verdicts = receipt
        .pointer("/result/details/securityVerdicts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let by_id = |items: &[Value], key: &str, id: &str| -> Value {
        items
            .iter()
            .find(|item| item.get(key).and_then(Value::as_str) == Some(id))
            .cloned()
            .unwrap_or(Value::Null)
    };
    Ok(confirmed
        .iter()
        .map(|finding| {
            let candidate = by_id(&candidates, "findingId", &finding.candidate_id);
            let verdict = by_id(&verdicts, "candidateId", &finding.candidate_id);
            let pick =
                |source: &Value, field: &str| source.get(field).cloned().unwrap_or(Value::Null);
            json!({
                "parentFindingId": format!("adjudicated:{}", finding.candidate_id),
                "candidateId": finding.candidate_id,
                "rule": pick(&candidate, "rule"),
                "provider": pick(&candidate, "provider"),
                "path": finding.path,
                "line": finding.line,
                "severity": finding.severity,
                "message": pick(&candidate, "message"),
                "evidenceExcerpt": pick(&candidate, "evidenceExcerpt"),
                "verdict": finding.verdict,
                "verdictDigest": finding.verdict_digest,
                "rationale": pick(&verdict, "rationale"),
                "threatModel": pick(&verdict, "threatModel"),
                "reachability": pick(&verdict, "reachability"),
                "impact": pick(&verdict, "impact"),
                "sink": pick(&verdict, "sink"),
                "proof": pick(&verdict, "proof"),
            })
        })
        .collect())
}

fn packet_path(dir: &Path) -> PathBuf {
    dir.join(LENS_PACKET_DIR)
        .join(format!("{VARIANT_PROVIDER_ID}.json"))
}

/// Compiles, freezes and writes the follow-up plan for `parent_run`, plus the
/// variant lens packet. Returns `None` when the parent run has no confirmed
/// security finding (no follow-up, no gap). `variant_spec` is the registry's
/// `legacy.security.variant-analysis` provider.
///
/// Idempotent: a follow-up that already matches the parent's current confirmed
/// findings is left untouched (so an ingested variant receipt survives); one
/// that does not is regenerated from scratch.
pub fn compile_followup(
    parent_run: &Path,
    variant_spec: &legion_contracts::ProviderSpec,
) -> Result<Option<FollowupPlanned>, AuditError> {
    if variant_spec.id.to_string() != VARIANT_PROVIDER_ID {
        return Err(invalid(format!(
            "follow-up provider must be {VARIANT_PROVIDER_ID}, not {}",
            variant_spec.id
        )));
    }
    let recomputed = recompute_run(parent_run)?;
    let confirmed = recomputed.confirmed_security;
    if confirmed.is_empty() {
        return Ok(None);
    }
    let paths = scoped_paths(&confirmed)?;
    let digest_of_confirmed = confirmed_digest(&confirmed)?;
    let parent_plan = read_json(&parent_run.join("plan.json"))?;
    let parent_digest = seal_digest(&parent_plan, "plan.json")?;
    let dir = parent_run.join(FOLLOWUP_DIR);

    if let Some(existing) = reuse(&dir, &parent_digest, &digest_of_confirmed, &paths) {
        return Ok(Some(existing));
    }

    let root = PathBuf::from(
        parent_plan
            .get("repository")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("plan.json has no repository root"))?,
    );
    let revision = parent_plan
        .pointer("/binding/repositoryRevision")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("plan.json has no repository revision"))?;
    let adjudication: PendingLensWork = serde_json::from_value(read_json(
        &parent_run
            .join(LENS_PACKET_DIR)
            .join(format!("{ADJUDICATOR_PROVIDER_ID}.json")),
    )?)
    .map_err(|error| invalid(format!("adjudication packet is invalid: {error}")))?;
    let inventory =
        FilesystemInventorySource::new(&root)?.inventory(&adjudication.request.repository_id)?;
    if inventory.generation != revision
        || parent_plan
            .pointer("/binding/inventoryDigest")
            .and_then(Value::as_str)
            != Some(inventory.digest.as_str())
    {
        return Err(AuditError::SourceDrift(
            "the working tree no longer matches the frozen revision; rerun the audit".into(),
        ));
    }

    // A fresh epoch for the follow-up run (also clears stale receipts); the
    // plan is signed with its key.
    let epoch = create_epoch(&dir)?;
    let (key, loaded) = load_epoch(&dir)?;
    debug_assert_eq!(epoch, loaded);
    let plan = AuditPlan::compile_followup(
        &inventory,
        variant_spec,
        &paths,
        &parent_digest,
        &digest_of_confirmed,
    )?
    .freeze(Some(key.as_slice()))?;
    let execution = execute(
        &plan,
        &inventory,
        &ReasoningProviderExecutor::unavailable(&root),
    )?;
    if execution.pending_host != [VARIANT_PROVIDER_ID] {
        return Err(invalid(
            "the follow-up plan did not leave the variant lens pending-host",
        ));
    }
    let mut work = pending_lens_work(&root, &plan, &inventory)?
        .into_iter()
        .find(|item| item.provider_id == VARIANT_PROVIDER_ID)
        .ok_or_else(|| invalid("the follow-up plan produced no variant lens packet"))?;
    if work.part().is_some() {
        // The follow-up chain binds exactly one variant packet; a partitioned
        // variant denominator would be silently under-covered.
        return Err(invalid(
            "the variant-analysis denominator needs more than one packet part, which the follow-up does not support",
        ));
    }
    let seeds = seeds(parent_run, &confirmed)?;
    let seed_count = seeds.len();
    let packet = work
        .request
        .packet
        .as_object_mut()
        .ok_or_else(|| invalid("variant lens packet is not an object"))?;
    packet.insert("variantSeeds".into(), Value::Array(seeds));
    packet.insert(
        "followup".into(),
        json!({
            "parentPlanDigest": parent_digest,
            "confirmedDigest": digest_of_confirmed,
            "confirmedPaths": paths,
        }),
    );
    work.request.request_id = expected_request_id(&work)?;
    let packet_digest =
        canonical_digest(&work.request.packet).map_err(|error| invalid(error.to_string()))?;
    let lens_work = json!([{
        "provider": work.provider_id,
        "lensIds": work.lens_ids,
        "status": "pending-host",
        "packet": packet_path(&dir),
        "packetDigest": packet_digest,
        "planDigest": work.request.plan_digest,
    }]);

    let repository = root.to_string_lossy().into_owned();
    let mut report = canonical_report(&repository, &execution)?;
    report.claims.insert("lensWork".into(), lens_work);
    report.claims.insert(
        "followupOf".into(),
        json!({"parentPlanDigest": parent_digest, "confirmedDigest": digest_of_confirmed}),
    );
    let plan_json = json!({
        "schemaVersion": 1,
        "kind": "audit-provider-plan",
        "repository": repository,
        "binding": {
            "repositoryRevision": execution.generation,
            "inventoryDigest": execution.inventory_digest,
        },
        "seal": {
            "digest": plan.digest(),
            "authenticity": "hmac-sha256",
            "signature": plan.signature(),
        },
        "providers": execution.planned_providers,
        "epoch": {"digest": epoch, "keyFile": super::ingest::EPOCH_KEY_FILE},
        "followupOf": {
            "kind": "security-variant-analysis",
            "parentPlanDigest": parent_digest,
            "confirmedDigest": digest_of_confirmed,
            "confirmedPaths": paths,
        },
    });
    let to_bytes = |value: &Value| {
        serde_json::to_vec_pretty(value).map_err(|error| invalid(error.to_string()))
    };
    write_atomic(
        &dir,
        FROZEN_PLAN_FILE,
        &to_bytes(&serde_json::to_value(plan.plan()).map_err(|error| invalid(error.to_string()))?)?,
    )?;
    write_atomic(
        &dir.join(LENS_PACKET_DIR),
        &format!("{VARIANT_PROVIDER_ID}.json"),
        &to_bytes(&serde_json::to_value(&work).map_err(|error| invalid(error.to_string()))?)?,
    )?;
    write_atomic(
        &dir,
        "execution.json",
        &to_bytes(&serde_json::to_value(&execution).map_err(|error| invalid(error.to_string()))?)?,
    )?;
    write_atomic(
        &dir,
        "report.json",
        &to_bytes(&serde_json::to_value(&report).map_err(|error| invalid(error.to_string()))?)?,
    )?;
    let plan_path = write_atomic(&dir, "plan.json", &to_bytes(&plan_json)?)?;
    Ok(Some(FollowupPlanned {
        dir: dir.clone(),
        plan_path,
        plan_digest: plan.digest().to_owned(),
        parent_plan_digest: parent_digest,
        confirmed_paths: paths,
        seeds: seed_count,
        provider: VARIANT_PROVIDER_ID.into(),
        packet: packet_path(&dir),
        packet_digest,
        reused: false,
    }))
}

/// An already-compiled follow-up that still matches the parent.
fn reuse(
    dir: &Path,
    parent_digest: &str,
    confirmed_digest: &str,
    paths: &[String],
) -> Option<FollowupPlanned> {
    let plan_json = read_json(&dir.join("plan.json")).ok()?;
    let frozen: AuditPlan =
        serde_json::from_value(read_json(&dir.join(FROZEN_PLAN_FILE)).ok()?).ok()?;
    let binding = frozen.followup_binding()?;
    let matches = binding.get("parentPlanDigest").and_then(Value::as_str) == Some(parent_digest)
        && binding.get("confirmedDigest").and_then(Value::as_str) == Some(confirmed_digest)
        && binding.get("confirmedPaths") == Some(&json!(paths))
        && crate::integrity::plan_digest(&frozen).ok().as_deref()
            == plan_json.pointer("/seal/digest").and_then(Value::as_str);
    if !matches || !packet_path(dir).is_file() {
        return None;
    }
    let work: PendingLensWork = serde_json::from_value(read_json(&packet_path(dir)).ok()?).ok()?;
    Some(FollowupPlanned {
        dir: dir.to_path_buf(),
        plan_path: dir.join("plan.json"),
        plan_digest: seal_digest(&plan_json, "plan.json").ok()?,
        parent_plan_digest: parent_digest.to_owned(),
        confirmed_paths: paths.to_vec(),
        seeds: work
            .request
            .packet
            .get("variantSeeds")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        provider: VARIANT_PROVIDER_ID.into(),
        packet: packet_path(dir),
        packet_digest: canonical_digest(&work.request.packet).ok()?,
        reused: true,
    })
}

/// What the parent `recompute_run` consults. Verifies the follow-up against
/// the parent: the signed follow-up plan, its binding to the parent plan digest
/// and to the confirmed verdicts, its exact path scope, and (through the
/// ordinary `recompute_run` on `<run>/followup`) the MAC'd variant receipt.
pub fn evaluate(
    run_dir: &Path,
    parent_plan: &Value,
    parent_execution: &ExecutionReport,
    confirmed: &[ConfirmedSecurityFinding],
) -> FollowupState {
    let dir = run_dir.join(FOLLOWUP_DIR);
    if !dir.join("plan.json").is_file() {
        return FollowupState::Absent;
    }
    check(&dir, parent_plan, parent_execution, confirmed)
        .unwrap_or_else(|error| FollowupState::Invalid(error.to_string()))
}

fn check(
    dir: &Path,
    parent_plan: &Value,
    parent_execution: &ExecutionReport,
    confirmed: &[ConfirmedSecurityFinding],
) -> Result<FollowupState, AuditError> {
    let parent_digest = seal_digest(parent_plan, "parent plan.json")?;
    if parent_digest != parent_execution.plan_digest {
        return Err(invalid(
            "parent plan.json seal differs from the executed parent plan",
        ));
    }
    let paths = scoped_paths(confirmed)?;
    let digest_of_confirmed = confirmed_digest(confirmed)?;

    let plan_json = read_json(&dir.join("plan.json"))?;
    let frozen: AuditPlan = serde_json::from_value(read_json(&dir.join(FROZEN_PLAN_FILE))?)
        .map_err(|error| invalid(format!("{FROZEN_PLAN_FILE} is invalid: {error}")))?;
    let (key, epoch) = load_epoch(dir)?;
    if plan_json.pointer("/epoch/digest").and_then(Value::as_str) != Some(epoch.as_str()) {
        return Err(invalid("follow-up epoch key does not match its plan.json"));
    }
    let digest = seal_digest(&plan_json, "follow-up plan.json")?;
    let signature = plan_json
        .pointer("/seal/signature")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("follow-up plan.json carries no signature"))?;
    crate::integrity::verify(&frozen, &digest, Some(signature), Some(key.as_slice()))?;

    let binding = frozen
        .bounds
        .get(FOLLOWUP_BOUND)
        .ok_or_else(|| invalid("follow-up plan carries no parent binding"))?;
    if binding.get("parentPlanDigest").and_then(Value::as_str) != Some(parent_digest.as_str()) {
        return Err(invalid(
            "follow-up plan is bound to a different parent plan digest",
        ));
    }
    if binding.get("confirmedDigest").and_then(Value::as_str) != Some(digest_of_confirmed.as_str())
    {
        return Err(invalid(
            "follow-up plan is bound to different confirmed verdicts",
        ));
    }
    if binding.get("confirmedPaths") != Some(&json!(paths)) {
        return Err(invalid(
            "follow-up plan is not scoped to the confirmed finding paths",
        ));
    }
    let [provider] = frozen.providers.as_slice() else {
        return Err(invalid("follow-up plan must hold exactly one provider"));
    };
    let frozen_paths: BTreeSet<&str> = provider
        .configuration
        .get("selector")
        .and_then(|selector| selector.get("paths"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if provider.id != VARIANT_PROVIDER_ID
        || provider
            .configuration
            .get("selector")
            .and_then(|selector| selector.get("op"))
            .and_then(Value::as_str)
            != Some("confirmedSecurityFinding")
        || frozen_paths != paths.iter().map(String::as_str).collect::<BTreeSet<_>>()
        || provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            != Some(paths.len() as u64)
    {
        return Err(invalid(
            "follow-up provider is not the variant analysis over the confirmed paths",
        ));
    }

    let execution: ExecutionReport =
        serde_json::from_value(read_json(&dir.join("execution.json"))?)
            .map_err(|error| invalid(format!("follow-up execution.json is invalid: {error}")))?;
    if execution.plan_digest != digest || execution.planned_providers != [VARIANT_PROVIDER_ID] {
        return Err(invalid("follow-up execution is not bound to its plan"));
    }
    let lens_packet = packet_path(dir);
    if !lens_packet.is_file() {
        return Err(io(
            std::io::Error::from(std::io::ErrorKind::NotFound),
            "follow-up has no variant lens packet",
        ));
    }

    // The ordinary verdict recomputation over the follow-up run: receipts must
    // verify (MAC, epoch, plan binding, result digest).
    let recomputed = recompute_run(dir)?;
    if !recomputed
        .ingested
        .iter()
        .any(|id| id == VARIANT_PROVIDER_ID)
    {
        return Ok(FollowupState::Pending(
            "the variant-analysis lens result has not been ingested".into(),
        ));
    }
    if !recomputed.pending.is_empty() || !recomputed.report.gaps.is_empty() {
        return Ok(FollowupState::Pending(format!(
            "the follow-up is incomplete: {}",
            recomputed.report.gaps.join("; ")
        )));
    }
    Ok(FollowupState::Complete(FollowupDone {
        plan_digest: digest,
        parent_plan_digest: parent_digest,
        confirmed_paths: paths,
        findings: recomputed.report.findings,
    }))
}

/// True when `<run>/followup` exists (compiled or not yet verified).
pub fn exists(run_dir: &Path) -> bool {
    fs::metadata(run_dir.join(FOLLOWUP_DIR).join("plan.json")).is_ok()
}
