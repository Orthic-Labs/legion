use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    pub run: PathBuf,
    /// Accepted for CLI consistency; verify output is always JSON.
    #[arg(long)]
    pub json: bool,
    /// Compare this run with another run by replay-equivalence digest
    /// (volatile fields removed); reports `equivalent` or `differs` with
    /// field paths. Byte-integrity checks are unaffected.
    #[arg(long, value_name = "OTHER_RUN")]
    pub replay: Option<PathBuf>,
}

/// Plan signing key for a run directory, under host custody (see
/// `legion_audit::resolve_plan_key`). A missing key is an error mentioning
/// `unverifiable-signature`; it is never treated as a pass.
fn verification_key(root: &std::path::Path) -> Result<Vec<u8>, CommandError> {
    legion_audit::plan_signing_key_for_run(root)
        .map_err(|error| CommandError::usage(error.to_string()))
}

/// Verify persisted Audit artifacts and reconcile facts against its frozen plan.
/// Provider execution cryptographic checks remain owned by `legion-audit`.
pub async fn run(args: VerifyArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    let args_replay = args.replay.clone();
    let supplied = if args.run.is_absolute() {
        args.run
    } else {
        std::env::current_dir()
            .map_err(super::io_error)?
            .join(args.run)
    };
    let (root, facts_path, plan_path) = if supplied.is_dir() {
        (
            supplied.clone(),
            supplied.join("facts.json"),
            supplied.join("plan.json"),
        )
    } else {
        let parent = supplied
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        (
            parent,
            supplied.clone(),
            supplied.with_file_name("plan.json"),
        )
    };
    if !facts_path.is_file() {
        return Err(CommandError::usage(format!(
            "verify facts artifact missing: {}",
            facts_path.display()
        )));
    }
    if !plan_path.is_file() && supplied.is_dir() {
        return Err(CommandError::usage(format!(
            "verify plan artifact missing: {}",
            plan_path.display()
        )));
    }
    let facts: Value = serde_json::from_slice(
        &std::fs::read(&facts_path).map_err(super::io_error)?,
    )
    .map_err(|error| CommandError::usage(format!("invalid verify facts artifact: {error}")))?;
    let plan: Value = if plan_path.is_file() {
        legion_audit::review_runtime::read_plan_json(&plan_path).map_err(|error| {
            CommandError::usage(format!("invalid verify plan artifact: {error}"))
        })?
    } else {
        facts.get("plan").cloned().ok_or_else(|| {
            CommandError::usage(format!(
                "verify plan artifact missing: {}",
                plan_path.display()
            ))
        })?
    };
    let mut errors = Vec::new();
    if facts.get("kind").and_then(Value::as_str) != Some("audit-facts") {
        errors.push("facts.kind must be audit-facts".into());
    }
    if !facts.get("checks").is_some_and(Value::is_array) {
        errors.push("facts.checks must be an array".into());
    }
    if !facts
        .get("provider_reconciliation")
        .and_then(Value::as_object)
        .and_then(|v| v.get("providerResults"))
        .is_some_and(Value::is_array)
    {
        errors.push("facts.provider_reconciliation.providerResults must be an array".into());
    }
    if plan.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        errors.push("plan.schemaVersion must be 1".into());
    }
    if plan.get("kind").and_then(Value::as_str) != Some("audit-provider-plan") {
        errors.push("plan.kind must be audit-provider-plan".into());
    }
    if plan.get("providers").and_then(Value::as_array).is_none() {
        errors.push("plan.providers must be an array".into());
    }
    if !plan
        .get("seal")
        .and_then(|v| v.get("digest"))
        .and_then(Value::as_str)
        .is_some_and(|v| v.starts_with("sha256:") && v.len() == 71)
    {
        errors.push("plan.seal.digest must use canonical sha256 form".into());
    }
    if !plan
        .get("binding")
        .and_then(|v| v.get("repositoryRevision"))
        .and_then(Value::as_str)
        .is_some_and(|v| !v.trim().is_empty())
    {
        errors.push("plan.binding.repositoryRevision is required".into());
    }
    let facts_plan = facts.get("plan");
    if let (Some(a), Some(b)) = (
        facts_plan
            .and_then(|v| v.get("seal"))
            .and_then(|v| v.get("digest")),
        plan.get("seal").and_then(|v| v.get("digest")),
    ) {
        if a != b {
            errors.push("facts.plan seal differs from plan seal".into());
        }
    }
    if facts_plan
        .and_then(|v| v.get("binding"))
        .and_then(|v| v.get("repositoryRevision"))
        != plan
            .get("binding")
            .and_then(|v| v.get("repositoryRevision"))
    {
        errors.push("facts.plan binding differs from plan binding".into());
    }
    let facts_digest = rightkit_evidence_contracts::canonical_digest_hex(&facts)
        .map_err(|e| CommandError::integrity(e.to_string()))?;
    let plan_digest = rightkit_evidence_contracts::canonical_digest_hex(&plan)
        .map_err(|e| CommandError::integrity(e.to_string()))?;
    let repository_id = facts
        .get("workspace")
        .and_then(Value::as_str)
        .or_else(|| plan.get("repository").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| root.to_string_lossy().into_owned());
    // Reasoning lenses count as ran only through ingested, MAC-verified receipts:
    // rebuild the verdict from the execution and the lens receipts and require
    // the stored report to agree with it.
    let verdict = lens_verdict(&root, &mut errors);
    let runtime_calls = runtime_calls(&root, &mut errors);
    // The plan key lives in host state (or AUDIT_PLAN_SIGNING_KEY). A run
    // whose key cannot be found is unverifiable, never a pass.
    let mut signature_unverifiable = false;
    let mut warnings: Vec<String> = Vec::new();
    let lens_key_custody = if plan.pointer("/epoch/digest").is_some() {
        use legion_audit::native_providers::reasoning::ingest::{
            load_epoch_with_source, EpochKeySource,
        };
        match load_epoch_with_source(&root) {
            Ok((_, _, EpochKeySource::HostState)) => "host-state",
            Ok((_, _, EpochKeySource::LegacyRunDir)) => {
                warnings.push(
                    "weak-custody: the lens receipt key was read from <run>/epoch.key beside the receipts it MACs; re-run to move it into host state"
                        .into(),
                );
                "legacy-run-dir"
            }
            Err(_) => "unavailable",
        }
    } else {
        "none"
    };
    let mut key_custody = "none";
    let mut key_source: Option<legion_audit::PlanKeySource> = None;
    let signing_key = if errors.is_empty() {
        match legion_audit::resolve_plan_key(&root, &plan) {
            legion_audit::PlanKeyResolution::Found { key, source } => {
                key_source = Some(source.clone());
                key_custody = match source {
                    legion_audit::PlanKeySource::Environment => "environment",
                    legion_audit::PlanKeySource::HostState => "host-state",
                    legion_audit::PlanKeySource::LegacyRunDirEpoch => {
                        warnings.push(
                            "weak-custody: plan key was read from <run>/epoch.key beside the data it signs; re-run to move it into host state"
                                .into(),
                        );
                        "legacy-run-dir"
                    }
                };
                Some(key)
            }
            legion_audit::PlanKeyResolution::Unverifiable { reason } => {
                signature_unverifiable = true;
                errors.push(format!("unverifiable-signature: {reason}"));
                None
            }
        }
    } else {
        None
    };
    let journal = verify_journal(
        &root,
        &plan,
        signing_key.as_deref(),
        key_source.as_ref(),
        &mut errors,
        &mut warnings,
    );
    if let Some(signing_key) = signing_key {
        let application = super::audit::audit_application_for(
            &repository_id,
            super::audit::inventory_filter_from_facts(&facts).as_ref(),
        )?;
        // Verify against the providers this run froze, not every configured
        // one: selection (`--only`/`--skip`, applicability) is part of the plan.
        let planned_ids = plan
            .get("providers")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        let providers = plan
            .get("providerSpecs")
            .cloned()
            .and_then(|specs| {
                serde_json::from_value::<Vec<rightkit_evidence_contracts::ProviderSpec>>(specs).ok()
            })
            .unwrap_or_else(|| application.provider_specs())
            .into_iter()
            .filter(|provider| planned_ids.is_empty() || planned_ids.contains(provider.id.as_str()))
            .collect::<Vec<_>>();
        let verification = application
            .invoke_with_cancellation(
                legion_application::NativeOperation::VerifyRequest {
                    repository_id: repository_id.clone(),
                    providers,
                    signing_key: Some(signing_key),
                    facts: facts.clone(),
                    plan: plan.clone(),
                },
                cancellation,
            )
            .await
            .map_err(|error| CommandError::incomplete(error.to_string()));
        if let Err(error) = verification {
            errors.push(error.message);
        }
    }
    // `valid` is integrity only. `status` and `complete` also reflect the
    // recomputed run verdict: "complete" only when that verdict is clean or
    // has findings (every lens ran); an incomplete or absent verdict is not.
    let verdict_status = verdict
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_owned);
    // A missing plan key can surface first in an earlier step (e.g. lens
    // verdict recomputation); it is still an unverifiable signature, not a
    // generic failure.
    let signature_unverifiable = signature_unverifiable
        || errors
            .iter()
            .any(|error| error.contains("unverifiable-signature:"));
    let (status, complete) = if signature_unverifiable {
        ("unverifiable-signature".to_owned(), false)
    } else if !errors.is_empty() {
        ("failed".to_owned(), false)
    } else {
        match verdict_status.as_deref() {
            Some("clean") | Some("findings") => ("complete".to_owned(), true),
            Some(other) => (other.to_owned(), false),
            None => ("incomplete".to_owned(), false),
        }
    };
    let gaps = if verdict.is_null() {
        vec!["no audit verdict: the directory has no execution.json and report.json".to_owned()]
    } else {
        Vec::new()
    };
    let replay = match &args_replay {
        Some(other) => replay_comparison(&root, other),
        None => Value::Null,
    };
    Ok(json!({
        "schemaVersion":1,
        "kind":"legion-verify",
        "keyCustody":key_custody,
        "lensKeyCustody":lens_key_custody,
        // Receipts and seals are keyed by the invoking user's key custody. No
        // out-of-process signer exists, so verification makes no claim of
        // protection against an agent running as the same user.
        "signingAuthority":legion_audit::native_providers::reasoning::ingest::SIGNING_AUTHORITY,
        "warnings":warnings,
        "replay":replay,
        "status":status,
        "complete":complete,
        "repository":repository_id,
        "factsDigest":facts_digest,
        "planContentDigest":plan_digest,
        "valid":errors.is_empty(),
        "contentErrors":errors,
        "verdict":verdict,
        "runtimeCalls":runtime_calls,
        "journal":journal,
        "gaps":gaps,
    }))
}

/// Verify the run's hash-chained event journal.
///
/// Whether a journal is REQUIRED is derived from the signature-verified native
/// plan (schema 2 or later) and from host-custody key binding, never from
/// unsigned outer markers (`plan.journal`, the report's `journalSealedAt`, a
/// continuation file, event files). A required journal that is missing or
/// defective fails verification; only a genuine schema-1 legacy run (legacy
/// run-directory key, no host binding) may report `journal-absent`. Continuation
/// and follow-up runs keep their journal in the parent run, which is verified
/// in their place. Verified: chain, plan binding, ordering, head seal,
/// finalization, the report's recorded head, the signed anchor, that
/// `report.json` matches the last `report_finalized`/`report_updated` digest,
/// and every retained provider receipt (signature, plan binding, journal
/// payload digest).
fn verify_journal(
    root: &Path,
    plan: &Value,
    key: Option<&[u8]>,
    key_source: Option<&legion_audit::PlanKeySource>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Value {
    use legion_audit::journal::{ANCHOR_FILE, EVENTS_FILE, HEAD_FILE};
    fn defect(errors: &mut Vec<String>, code: &str, detail: String) {
        errors.push(format!("journal-defect:{code}: {detail}"));
    }
    let files_present = [EVENTS_FILE, HEAD_FILE, ANCHOR_FILE]
        .iter()
        .any(|name| std::fs::symlink_metadata(root.join(name)).is_ok());
    let host_custody = plan.get("planKey").is_some_and(|value| !value.is_null());
    let legacy_key = matches!(
        key_source,
        Some(legion_audit::PlanKeySource::LegacyRunDirEpoch)
    );
    let native_present = plan.get("nativePlan").is_some_and(|value| !value.is_null());
    let plan_digest = plan.pointer("/seal/digest").and_then(Value::as_str);

    // Signed facts: only a native plan whose signature verifies under the run
    // key says what this run is.
    let mut signed: Option<legion_audit::AuditPlan> = None;
    if let (true, Some(key), Some(digest)) = (native_present, key, plan_digest) {
        let native = &plan["nativePlan"];
        let parsed = native
            .get("plan")
            .cloned()
            .ok_or_else(|| "nativePlan body is missing".to_owned())
            .and_then(|body| {
                serde_json::from_value::<legion_audit::AuditPlan>(body)
                    .map_err(|error| format!("nativePlan body is invalid: {error}"))
            })
            .and_then(|body| {
                if native.get("digest").and_then(Value::as_str) != Some(digest) {
                    return Err("nativePlan digest differs from the plan seal".to_owned());
                }
                legion_audit::verify(
                    &body,
                    digest,
                    native.get("signature").and_then(Value::as_str),
                    Some(key),
                )
                .map(|_| body)
                .map_err(|error| error.to_string())
            });
        match parsed {
            Ok(body) => signed = Some(body),
            Err(error) => defect(errors, "plan_unsigned", error),
        }
    }
    let schema = signed.as_ref().map(|body| body.schema_version);
    let modern = match &signed {
        Some(body) => body.schema_version >= 2 || host_custody,
        None => host_custody || !legacy_key || native_present,
    };
    if schema.is_some_and(|version| version >= 2) && legacy_key {
        defect(
            errors,
            "weak_custody_current_plan",
            "a schema-2 plan cannot be verified under a run-directory key".into(),
        );
    }

    // Where the journal lives: the run itself, or the parent for a validated
    // continuation or a signed follow-up binding.
    let mut home: Option<(PathBuf, &'static str)> = None;
    if !files_present {
        if root
            .join(legion_audit::continuation::CONTINUATION_FILE)
            .is_file()
        {
            match legion_audit::continuation::validate_lineage(root) {
                Ok(Some(lineage)) => {
                    if let Some(parent) = lineage.get("parent").and_then(Value::as_str) {
                        home = Some((PathBuf::from(parent), "continuation"));
                    }
                }
                Ok(None) => {}
                Err(error) => defect(errors, "continuation_lineage", error.to_string()),
            }
        } else if let Some(binding) = signed.as_ref().and_then(|body| body.followup_binding()) {
            let parent = (root.file_name().is_some_and(|name| {
                name == legion_audit::native_providers::reasoning::followup::FOLLOWUP_DIR
            }))
            .then(|| root.parent().map(Path::to_path_buf))
            .flatten();
            match (
                parent,
                binding.get("parentPlanDigest").and_then(Value::as_str),
            ) {
                (Some(parent), Some(expected)) => {
                    let parent_digest = std::fs::read(parent.join("plan.json"))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                        .and_then(|value| {
                            value
                                .pointer("/seal/digest")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        });
                    if parent_digest.as_deref() == Some(expected) {
                        home = Some((parent, "followup"));
                    } else {
                        defect(
                            errors,
                            "followup_parent",
                            "the follow-up's signed parent binding does not match the parent plan"
                                .into(),
                        );
                    }
                }
                _ => defect(
                    errors,
                    "followup_parent",
                    "the follow-up run is outside its fixed parent directory".into(),
                ),
            }
        }
    }
    if let Some((parent, reason)) = home {
        let parent_plan: Option<Value> = std::fs::read(parent.join("plan.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let parent_key = legion_audit::plan_signing_key_for_run(&parent);
        let parent_digest = parent_plan
            .as_ref()
            .and_then(|value| value.pointer("/seal/digest"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        return match (parent_digest, parent_key) {
            (Some(digest), Ok(parent_key)) => {
                let mut value = verify_journal_dir(
                    &parent,
                    &digest,
                    Some(parent_key.as_slice()),
                    None,
                    None,
                    errors,
                );
                value["home"] = json!(reason);
                warnings.push(format!(
                    "journal-in-parent: {reason} run; its journal and receipts were verified in the parent run"
                ));
                value
            }
            _ => {
                defect(
                    errors,
                    "parent_unverifiable",
                    format!("the parent run's journal cannot be verified for this {reason} run"),
                );
                json!({"status": "failed", "home": reason})
            }
        };
    }

    let report_bytes = std::fs::read(root.join("report.json")).ok();
    let claim = report_bytes
        .as_deref()
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .and_then(|report| report.pointer("/claims/journalSealedAt").cloned())
        .filter(|value| !value.is_null());
    let plan_marker = plan.get("journal").is_some_and(|value| !value.is_null());
    if !modern && !files_present && claim.is_none() && !plan_marker {
        warnings.push(
            "journal-absent: legacy schema-1 run records no event journal (it predates journaling); its history is not verifiable"
                .into(),
        );
        return json!({"status": "absent", "legacy": true});
    }
    let Some(plan_digest) = plan_digest else {
        defect(
            errors,
            "plan_mismatch",
            "plan.seal.digest is missing".into(),
        );
        return json!({"status": "failed"});
    };
    verify_journal_dir(
        root,
        plan_digest,
        key,
        claim.as_ref(),
        Some(report_bytes.as_deref()),
        errors,
    )
}

/// Verify one journal directory. `report` is `Some` only for the run that owns
/// the journal: its `report.json` bytes (`None` when unreadable) must match the
/// digest the journal last vouched for.
fn verify_journal_dir(
    dir: &Path,
    plan_digest: &str,
    key: Option<&[u8]>,
    claim: Option<&Value>,
    report: Option<Option<&[u8]>>,
    errors: &mut Vec<String>,
) -> Value {
    use legion_audit::journal::{
        bytes_digest, current_report_digest, verify_dir, Expectation, JournalAnchor, SealedHead,
        ANCHOR_FILE,
    };
    fn defect(errors: &mut Vec<String>, code: &str, detail: String) {
        errors.push(format!("journal-defect:{code}: {detail}"));
    }
    let expected_head = match claim {
        None => None,
        Some(claim) => match (
            claim.get("sequence").and_then(Value::as_u64),
            claim.get("digest").and_then(Value::as_str),
        ) {
            (Some(sequence), Some(digest)) => Some(SealedHead {
                plan_digest: plan_digest.to_owned(),
                sequence,
                digest: Some(digest.to_owned()),
                finalized: false,
            }),
            _ => {
                defect(
                    errors,
                    "expected_head_mismatch",
                    "the report's recorded journal head is malformed".into(),
                );
                None
            }
        },
    };
    let anchor = match JournalAnchor::read(dir) {
        Ok(anchor) => anchor,
        Err(error) => {
            defect(errors, "anchor_invalid", error.to_string());
            None
        }
    };
    match (&anchor, key) {
        (Some(anchor), Some(key)) => {
            if !anchor.verify(key) {
                defect(
                    errors,
                    "anchor_signature",
                    "the journal anchor does not verify under the run plan key".into(),
                );
            }
            if anchor.plan_digest != plan_digest {
                defect(
                    errors,
                    "plan_mismatch",
                    "the journal anchor is bound to a different plan".into(),
                );
            }
        }
        (Some(_), None) => defect(
            errors,
            "anchor_unverifiable",
            "the run plan key is unavailable, so the anchor cannot be checked".into(),
        ),
        (None, _) => defect(
            errors,
            "anchor_missing",
            format!(
                "{ANCHOR_FILE} is missing: the run was never finalized or the anchor was removed"
            ),
        ),
    }
    let expectation = Expectation {
        require_finalized: true,
        expected_head,
        final_plan_digest: anchor
            .as_ref()
            .map(|anchor| anchor.effective_plan_digest.clone()),
    };
    let verification = verify_dir(dir, plan_digest, &expectation);
    for item in &verification.defects {
        let code = serde_json::to_value(item.code)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".into());
        defect(errors, &code, item.detail.clone());
    }
    if verification.unsealed_tail > 0 {
        defect(
            errors,
            "seal_mismatch",
            format!(
                "{} committed event(s) lie past the sealed head",
                verification.unsealed_tail
            ),
        );
    }
    if let Some(anchor) = &anchor {
        let last = verification.events.last();
        if verification.events.len() as u64 != anchor.sequence
            || last.map(|event| event.digest.as_str()) != Some(anchor.digest.as_str())
        {
            defect(
                errors,
                "anchor_mismatch",
                "the journal does not end at the signed anchor head".into(),
            );
        }
    }
    // The report must be the one the journal last vouched for: the finalized
    // digest, or the newest `report_updated` (lens ingest rewrites the report
    // after finalization and journals each rewrite).
    if let Some(report_bytes) = report {
        match (report_bytes, current_report_digest(&verification.events)) {
            (Some(bytes), Some(vouched)) if vouched != bytes_digest(bytes) => defect(
                errors,
                "report_digest_mismatch",
                "report.json matches neither the report_finalized digest nor the last report_updated digest"
                    .into(),
            ),
            (None, _) => defect(errors, "report_missing", "report.json is unreadable".into()),
            _ => {}
        }
    }
    match key {
        Some(key) => {
            for detail in
                legion_audit::resume::verify_retained_receipts(dir, key, &verification.events)
            {
                defect(errors, "receipt", detail);
            }
        }
        None => defect(
            errors,
            "receipt_unverifiable",
            "the run plan key is unavailable, so retained provider receipts cannot be checked"
                .into(),
        ),
    }
    json!({
        "status": if verification.is_valid() && errors.iter().all(|e| !e.starts_with("journal-defect:")) { "verified" } else { "failed" },
        "eventCount": verification.events.len(),
        "headSequence": verification.head.as_ref().map(|head| head.sequence),
        "headDigest": verification.head.as_ref().and_then(|head| head.digest.clone()),
        "finalized": verification.finalized,
        "defects": verification.defects.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
    })
}

/// Replay-equivalence comparison of two runs; never affects integrity status.
fn replay_comparison(run: &Path, other: &Path) -> Value {
    let other = if other.is_absolute() {
        other.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(other),
            Err(error) => return json!({"status":"unverifiable","error":error.to_string()}),
        }
    };
    let other = if other.is_file() {
        other.parent().map(Path::to_path_buf).unwrap_or(other)
    } else {
        other
    };
    let load = |dir: &Path| legion_audit::replay_run_value(dir);
    match (load(run), load(&other)) {
        (Ok(left), Ok(right)) => {
            let differences = legion_audit::replay_differences(&left, &right);
            let digests = (
                legion_audit::replay_digest(&left),
                legion_audit::replay_digest(&right),
            );
            match digests {
                (Ok(a), Ok(b)) => json!({
                    "status": if differences.is_empty() && a == b { "equivalent" } else { "differs" },
                    "digest": a,
                    "otherDigest": b,
                    "differences": differences,
                }),
                (Err(error), _) | (_, Err(error)) => {
                    json!({"status":"unverifiable","error":error.to_string()})
                }
            }
        }
        (Err(error), _) | (_, Err(error)) => {
            json!({"status":"unverifiable","error":error.to_string()})
        }
    }
}

const MAX_RUNTIME_CALLS: usize = 4_096;
const MAX_RUNTIME_RECEIPT_BYTES: u64 = 256 * 1024;

fn read_runtime_call(path: &Path) -> Result<Value, String> {
    read_bounded_runtime_json(path, MAX_RUNTIME_RECEIPT_BYTES)
}

fn read_runtime_plan(path: &Path) -> Result<Value, String> {
    legion_audit::review_runtime::read_plan_json(path).map_err(|error| error.to_string())
}

fn read_bounded_runtime_json(path: &Path, limit: u64) -> Result<Value, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err("runtime accounting input must be a bounded regular nonsymlink file".into());
    }
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !opened.is_file() || opened.len() > limit {
        return Err("opened receipt exceeds regular-file byte bound".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit
        || std::fs::symlink_metadata(path)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_symlink()
    {
        return Err("receipt changed outside regular-file byte bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid receipt JSON: {error}"))
}

#[derive(Default)]
struct RuntimeCallIds {
    calls: BTreeSet<String>,
    receipts: BTreeSet<String>,
    reservations: BTreeSet<String>,
}
impl RuntimeCallIds {
    fn record(&mut self, receipt: &Value) -> Result<legion_audit::next::UsageReceipt, String> {
        let bounded_id = |value: Option<&Value>| {
            value
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty() && id.len() <= 512)
                .map(str::to_owned)
        };
        let call = bounded_id(receipt.get("callId")).ok_or("runtime call ID missing/invalid")?;
        let reservation = bounded_id(receipt.pointer("/authorization/reservationId"))
            .ok_or("runtime reservation ID missing/invalid")?;
        let usage: legion_audit::next::UsageReceipt =
            serde_json::from_value(receipt["observation"]["usage"].clone())
                .map_err(|_| "runtime usage receipt malformed")?;
        if usage.receipt_id.trim().is_empty() || usage.receipt_id.len() > 512 {
            return Err("runtime usage receipt ID missing/invalid".into());
        }
        let usage_id = usage.receipt_id.clone();
        if usage.reservation_id != reservation {
            return Err("runtime usage reservation differs from authorization".into());
        }
        if self.calls.contains(&call) {
            return Err("duplicate runtime callId".into());
        }
        if self.receipts.contains(&usage_id) {
            return Err("duplicate runtime usage receiptId".into());
        }
        if self.reservations.contains(&reservation) {
            return Err("duplicate runtime reservationId".into());
        }
        self.calls.insert(call);
        self.receipts.insert(usage_id);
        self.reservations.insert(reservation);
        Ok(usage)
    }
}

/// Only typed accounting & identity fields leave authenticated diagnostics.
/// In particular rawUsage, modelAction, prompts & responses are never projected.
fn runtime_call_projection(receipt: &Value, usage: &legion_audit::next::UsageReceipt) -> Value {
    let observation = &receipt["observation"];
    let created = &observation["processCreationTime"];
    json!({
        "callId":receipt["callId"].as_str(),
        "execution":{
            "stage":receipt["execution"]["stage"].as_str(),
            "modelTier":receipt["execution"]["modelTier"].as_str(),
            "authorizedModel":receipt["execution"]["model"].as_str()
        },
        "processIdentity":{
            "processId":observation["processId"].as_u64(),
            "contextId":observation["contextId"].as_str(),
            "processCreated":observation["processCreated"].as_bool(),
            "processCreationTicks":observation["processCreationTicks"].as_u64(),
            "processCreationTime":if created.is_null() { Value::Null } else { json!({
                "source":created["source"].as_str(),"unixSeconds":created["unixSeconds"].as_u64(),"nanoseconds":created["nanoseconds"].as_u64()
            }) }
        },
        "usage":usage,
        "reportedApiEquivalentCostUsd":observation["reportedApiEquivalentCostUsd"].as_str(),
        "observedModels":observation["observedModels"].as_array().map(|models| models.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        "modelPolicyViolation":observation["modelPolicyViolation"].as_str()
    })
}

fn optional_runtime_json(path: &Path, limit: u64) -> Result<Option<Value>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => read_bounded_runtime_json(path, limit).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn optional_runtime_plan(path: &Path) -> Result<Option<Value>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => read_runtime_plan(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

const MAX_RUNTIME_RUN_DEPTH: usize = 64;
const MAX_RUNTIME_STATE_BYTES: u64 = 16 * 1024 * 1024;

/// Follow-ups use their own epoch, but may charge their parent's ledger. Only
/// the fixed child directory & signed frozen parent binding establish that edge.
fn runtime_followup_binding(parent: &Path, child: &Path) -> Result<(), String> {
    use legion_audit::native_providers::reasoning::{followup, ingest};
    let metadata = std::fs::symlink_metadata(child).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("runtime follow-up must be a regular nonsymlink directory".into());
    }
    let parent_plan = read_runtime_plan(&parent.join("plan.json"))?;
    let child_plan = read_runtime_plan(&child.join("plan.json"))?;
    let frozen: legion_audit::AuditPlan =
        serde_json::from_value(read_runtime_plan(&child.join(followup::FROZEN_PLAN_FILE))?)
            .map_err(|error| format!("runtime follow-up frozen plan invalid: {error}"))?;
    let (key, epoch) = ingest::load_epoch(child).map_err(|error| error.to_string())?;
    let digest = child_plan
        .pointer("/seal/digest")
        .and_then(Value::as_str)
        .ok_or("runtime follow-up plan digest missing")?;
    let signature = child_plan
        .pointer("/seal/signature")
        .and_then(Value::as_str)
        .ok_or("runtime follow-up plan signature missing")?;
    legion_audit::verify(&frozen, digest, Some(signature), Some(&key))
        .map_err(|error| error.to_string())?;
    let parent_digest = parent_plan
        .pointer("/seal/digest")
        .and_then(Value::as_str)
        .ok_or("runtime parent plan digest missing")?;
    // Parent verification also uses the existing plan MAC owner. Checking its
    // body prevents an edited outer seal from redirecting a child to a ledger.
    let parent_frozen: legion_audit::AuditPlan = serde_json::from_value(
        parent_plan
            .pointer("/nativePlan/plan")
            .cloned()
            .ok_or("runtime parent native plan missing")?,
    )
    .map_err(|error| format!("runtime parent native plan invalid: {error}"))?;
    let parent_signature = parent_plan
        .pointer("/seal/signature")
        .and_then(Value::as_str)
        .ok_or("runtime parent plan signature missing")?;
    let parent_key = if parent_plan.get("followupOf").is_some() {
        ingest::load_epoch(parent)
            .map_err(|error| error.to_string())?
            .0
    } else {
        verification_key(parent).map_err(|error| error.message)?
    };
    legion_audit::verify(
        &parent_frozen,
        parent_digest,
        Some(parent_signature),
        Some(&parent_key),
    )
    .map_err(|error| error.to_string())?;
    let binding = frozen
        .followup_binding()
        .ok_or("runtime follow-up frozen parent binding missing")?;
    if child_plan.pointer("/epoch/digest").and_then(Value::as_str) != Some(epoch.as_str())
        || binding["parentPlanDigest"].as_str() != Some(parent_digest)
        || child_plan
            .pointer("/followupOf/parentPlanDigest")
            .and_then(Value::as_str)
            != Some(parent_digest)
        || child_plan.pointer("/nativePlan/plan")
            != Some(&serde_json::to_value(&frozen).map_err(|error| error.to_string())?)
    {
        return Err("runtime follow-up differs from its frozen parent/epoch binding".into());
    }
    Ok(())
}

fn runtime_accounting_root(run: &Path) -> Result<PathBuf, String> {
    use legion_audit::native_providers::reasoning::followup;
    let mut root = runtime_run_path(run)?;
    let mut visited = BTreeSet::new();
    for _ in 0..MAX_RUNTIME_RUN_DEPTH {
        if !visited.insert(root.clone()) {
            return Err("runtime accounting ancestry cycle".into());
        }
        if let Some(parent) = runtime_continuation_parent(&root)? {
            root = parent;
            continue;
        }
        let plan = optional_runtime_plan(&root.join("plan.json"))?;
        let frozen = optional_runtime_plan(&root.join(followup::FROZEN_PLAN_FILE))?;
        let has_binding = plan.as_ref().is_some_and(|plan| {
            plan.get("followupOf").is_some()
                || plan.pointer("/nativePlan/plan/bounds/followup").is_some()
        }) || frozen
            .as_ref()
            .is_some_and(|plan| plan.pointer("/bounds/followup").is_some());
        if !has_binding {
            return Ok(root);
        }
        if root
            .file_name()
            .is_none_or(|name| name != followup::FOLLOWUP_DIR)
        {
            return Err("runtime follow-up is outside its fixed parent directory".into());
        }
        let parent = root
            .parent()
            .ok_or("runtime follow-up parent directory missing")?;
        runtime_followup_binding(parent, &root)?;
        root = parent.to_path_buf();
    }
    Err("runtime accounting ancestry exceeds 64-run bound".into())
}

fn runtime_run_path(run: &Path) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(run).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("runtime run must be a regular nonsymlink directory".into());
    }
    std::fs::canonicalize(run).map_err(|error| error.to_string())
}

fn runtime_continuation_parent(run: &Path) -> Result<Option<PathBuf>, String> {
    // Bound local control files before delegating semantic/hash checks to owner.
    optional_runtime_json(
        &run.join(legion_audit::continuation::CONTINUATION_FILE),
        MAX_RUNTIME_STATE_BYTES,
    )?;
    let lineage = legion_audit::continuation::validate_lineage(run)
        .map_err(|error| format!("runtime continuation invalid: {error}"))?;
    lineage
        .map(|lineage| {
            let parent = lineage["parent"]
                .as_str()
                .ok_or("runtime continuation parent missing")?;
            runtime_run_path(Path::new(parent))
        })
        .transpose()
}

fn runtime_continuation_child(run: &Path) -> Result<Option<PathBuf>, String> {
    let Some(owner) = optional_runtime_json(
        &run.join("continuation-active.json"),
        MAX_RUNTIME_STATE_BYTES,
    )?
    else {
        return Ok(None);
    };
    let child = runtime_run_path(Path::new(
        owner["child"]
            .as_str()
            .ok_or("runtime continuation owner child missing")?,
    ))?;
    if runtime_continuation_parent(&child)?.as_deref() != Some(run) {
        return Err("runtime continuation ownership has no validated child lineage".into());
    }
    Ok(Some(child))
}

struct RuntimeRunEvidence {
    run: PathBuf,
    continuation_parent: Option<PathBuf>,
    calls: Vec<Value>,
    receipt_count: usize,
    summary: Option<Value>,
}

fn collect_runtime_runs(
    run: &Path,
    depth: usize,
    ids: &mut RuntimeCallIds,
    entries: &mut usize,
    visited: &mut BTreeSet<PathBuf>,
    runs: &mut Vec<RuntimeRunEvidence>,
    errors: &mut Vec<String>,
) -> Result<(), String> {
    use legion_audit::native_providers::reasoning::{followup, ingest};
    if depth >= MAX_RUNTIME_RUN_DEPTH {
        return Err("runtime accounting traversal exceeds 64-run bound".into());
    }
    let canonical = runtime_run_path(run)?;
    if !visited.insert(canonical.clone()) || visited.len() > MAX_RUNTIME_CALLS {
        return Err("runtime accounting cycle/duplicate or 4096-run bound exceeded".into());
    }
    let run = canonical.as_path();
    let mut evidence = RuntimeRunEvidence {
        run: run.to_path_buf(),
        continuation_parent: runtime_continuation_parent(run)?,
        calls: Vec::new(),
        receipt_count: 0,
        summary: optional_runtime_json(&run.join("review-runtime.json"), MAX_RUNTIME_STATE_BYTES)?,
    };
    let directory = run.join("runtime-calls");
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("runtime-calls directory unavailable: {error}")),
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("runtime-calls must be a regular nonsymlink directory".into());
            }
            let mut paths = Vec::new();
            for entry in std::fs::read_dir(&directory).map_err(|error| error.to_string())? {
                *entries += 1;
                if *entries > MAX_RUNTIME_CALLS {
                    return Err("runtime-calls exceeds 4096-entry bound across runs".into());
                }
                let path = entry.map_err(|error| error.to_string())?.path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                {
                    paths.push(path);
                }
            }
            paths.sort();
            evidence.receipt_count = paths.len();
            for path in paths {
                let checked = (|| -> Result<Value, String> {
                    let envelope = read_runtime_call(&path)?;
                    let receipt = ingest::verify_runtime_call(run, &envelope)
                        .map_err(|error| error.to_string())?;
                    let usage = ids.record(&receipt)?;
                    let mut projected = runtime_call_projection(&receipt, &usage);
                    projected["receiptRun"] = json!(run);
                    Ok(projected)
                })();
                match checked {
                    Ok(call) => evidence.calls.push(call),
                    Err(error) => {
                        errors.push(format!("runtime call receipt {}: {error}", path.display()))
                    }
                }
            }
        }
    }
    runs.push(evidence);
    let child = run.join(followup::FOLLOWUP_DIR);
    match std::fs::symlink_metadata(&child) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
        Ok(_) => {
            runtime_followup_binding(run, &child)?;
            collect_runtime_runs(&child, depth + 1, ids, entries, visited, runs, errors)?;
        }
    }
    if let Some(child) = runtime_continuation_child(run)? {
        collect_runtime_runs(&child, depth + 1, ids, entries, visited, runs, errors)?;
    }
    Ok(())
}

fn runtime_summary_count(summary: &Value) -> Result<u64, String> {
    match summary.get("calls") {
        None => Ok(0),
        Some(count) => count
            .as_u64()
            .filter(|count| *count <= MAX_RUNTIME_CALLS as u64)
            .ok_or_else(|| "runtime summary physical call count invalid".into()),
    }
}

/// Summaries count only their last invocation; receipts & reservations persist
/// across resume. Reconcile every native charge exactly once across bound runs.
fn reconcile_runtime_accounting(
    runs: &[RuntimeRunEvidence],
    errors: &mut Vec<String>,
) -> Result<usize, String> {
    let mut expected = BTreeMap::new();
    let mut ids = RuntimeCallIds::default();
    let mut ledger_entries = BTreeMap::<String, (usize, Value)>::new();
    for (index, evidence) in runs.iter().enumerate() {
        let observed_processes = evidence
            .calls
            .iter()
            .filter(|call| {
                call.pointer("/processIdentity/processId")
                    .and_then(Value::as_u64)
                    .is_some_and(|id| id > 0)
            })
            .count() as u64;
        if let Some(summary) = &evidence.summary {
            if summary["kind"] != "legion-audit-runtime" {
                return Err("runtime summary kind invalid".into());
            }
            if runtime_summary_count(summary)? > observed_processes {
                errors.push(
                    "runtime summary physical call count exceeds authenticated runtime receipts"
                        .into(),
                );
            }
            if let Some(followup) = summary.get("followup") {
                let child_processes = runs
                    .iter()
                    .find(|child| child.run == evidence.run.join("followup"))
                    .map(|child| {
                        child
                            .calls
                            .iter()
                            .filter(|call| {
                                call.pointer("/processIdentity/processId")
                                    .and_then(Value::as_u64)
                                    .is_some_and(|id| id > 0)
                            })
                            .count() as u64
                    })
                    .unwrap_or(0);
                if runtime_summary_count(followup)? > child_processes {
                    errors.push("runtime follow-up summary physical call count exceeds authenticated child receipts".into());
                }
            }
        }
        let state = optional_runtime_json(
            &evidence.run.join(legion_audit::next::STATE_FILE),
            MAX_RUNTIME_STATE_BYTES,
        )?;
        let Some(state) = state else {
            // Shared-budget children may have no local ledger, but their calls
            // still must match the authenticated ancestor ledger below.
            if index == 0
                && (evidence.receipt_count > 0
                    || evidence
                        .summary
                        .as_ref()
                        .is_some_and(|summary| runtime_summary_count(summary).unwrap_or(0) > 0))
            {
                return Err(
                    "native runtime evidence has no persisted next-state.json accounting ledger"
                        .into(),
                );
            }
            continue;
        };
        if state["kind"] != "legion-audit-next-state"
            || !matches!(state["schemaVersion"].as_u64(), Some(1 | 2))
        {
            return Err("runtime accounting state identity invalid".into());
        }
        let reservations = match state.get("reservations") {
            Some(Value::Object(reservations)) => reservations,
            None if state["schemaVersion"] == 1
                && state.get("issuances").and_then(Value::as_u64).unwrap_or(0) == 0 =>
            {
                continue;
            }
            _ => return Err("runtime accounting reservations missing/malformed".into()),
        };
        for (id, entry) in reservations {
            if let Some((owner_index, previous)) = ledger_entries.get(id) {
                if previous != entry
                    || evidence.continuation_parent.as_deref()
                        != Some(runs[*owner_index].run.as_path())
                {
                    return Err("runtime accounting duplicate reservation differs or lacks validated inheritance".into());
                }
                continue;
            }
            ledger_entries.insert(id.clone(), (index, entry.clone()));
            if ledger_entries.len() > MAX_RUNTIME_CALLS {
                return Err(
                    "runtime accounting reservations exceed 4096-entry bound across runs".into(),
                );
            }
            if entry["transportAuthorized"] != true || entry["nativeCostRequired"] != true {
                continue;
            }
            let bound = json!({"callId":entry["callId"],"authorization":{"reservationId":id},"observation":{"usage":entry["usage"]}});
            let usage = ids
                .record(&bound)
                .map_err(|error| format!("native accounting reservation invalid: {error}"))?;
            let cost = match entry.get("reportedApiCostUsd") {
                Some(Value::String(cost)) => Some(cost.clone()),
                None | Some(Value::Null) => None,
                _ => return Err(
                    "native accounting reservation cost must be exact decimal string or unknown"
                        .into(),
                ),
            };
            expected.insert(
                id.clone(),
                (
                    index,
                    entry["callId"].as_str().unwrap().to_owned(),
                    usage,
                    cost,
                ),
            );
        }
    }
    let mut matched = BTreeSet::new();
    for (run_index, call) in runs
        .iter()
        .enumerate()
        .flat_map(|(index, run)| run.calls.iter().map(move |call| (index, call)))
    {
        let usage: legion_audit::next::UsageReceipt = serde_json::from_value(call["usage"].clone())
            .map_err(|_| "authenticated runtime usage projection malformed")?;
        let Some((ledger_index, call_id, expected_usage, expected_cost)) =
            expected.get(&usage.reservation_id)
        else {
            errors.push("authenticated native runtime receipt has no matching native accounting reservation".into());
            continue;
        };
        if *ledger_index > run_index
            || call["callId"].as_str() != Some(call_id.as_str())
            || &usage != expected_usage
            || call["reportedApiEquivalentCostUsd"].as_str() != expected_cost.as_deref()
        {
            errors.push("authenticated native runtime receipt differs from persisted callId, usage or exact API-equivalent cost".into());
            continue;
        }
        matched.insert(usage.reservation_id);
    }
    if matched.len() != expected.len() {
        errors.push(format!(
            "native accounting reservations missing matching authenticated runtime receipts: {}",
            expected.len() - matched.len()
        ));
    }
    Ok(expected.len())
}

/// Authenticate with each run's own epoch; account the bound budget tree once.
fn runtime_calls(run: &Path, errors: &mut Vec<String>) -> Value {
    let before = errors.len();
    let mut runs = Vec::new();
    let mut entries = 0;
    let mut accounting_root = run.to_path_buf();
    let checked = (|| -> Result<usize, String> {
        accounting_root = runtime_accounting_root(run)?;
        collect_runtime_runs(
            &accounting_root,
            0,
            &mut RuntimeCallIds::default(),
            &mut entries,
            &mut BTreeSet::new(),
            &mut runs,
            errors,
        )?;
        reconcile_runtime_accounting(&runs, errors)
    })();
    let expected = match checked {
        Ok(count) => Some(count),
        Err(error) => {
            errors.push(error);
            None
        }
    };
    let receipt_count: usize = runs.iter().map(|run| run.receipt_count).sum();
    let calls: Vec<Value> = runs.into_iter().flat_map(|run| run.calls).collect();
    json!({"status":if errors.len()>before { "invalid" } else if calls.is_empty() { "not-run" } else { "verified" },"accountingRoot":accounting_root,"count":calls.len(),"receiptCount":receipt_count,"nativeReservationCount":expected,"calls":calls})
}

/// Recomputes the run verdict from `execution.json` plus the ingested lens
/// receipts. Returns `Null` when the directory holds no Audit run.
fn lens_verdict(run: &std::path::Path, errors: &mut Vec<String>) -> Value {
    if !run.join("execution.json").is_file() || !run.join("report.json").is_file() {
        return Value::Null;
    }
    let recomputed = match legion_audit::native_providers::reasoning::ingest::recompute_run(run) {
        Ok(recomputed) => recomputed,
        Err(error) => {
            errors.push(format!("lens verdict could not be recomputed: {error}"));
            return Value::Null;
        }
    };
    let stored: Value = std::fs::read(run.join("report.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    let status = serde_json::to_value(recomputed.report.status).unwrap_or(Value::Null);
    let lenses_ran = recomputed
        .report
        .claims
        .get("lensesRan")
        .cloned()
        .unwrap_or(Value::Null);
    let recomputed_visual_findings = serde_json::to_value(
        recomputed
            .report
            .findings
            .iter()
            .filter(|finding| finding.provider.as_deref() == Some("legacy.visual.core"))
            .collect::<Vec<_>>(),
    )
    .ok()
    .and_then(|value| value.as_array().cloned());
    let visual_findings_match = recomputed_visual_findings
        .as_deref()
        .is_some_and(|expected| matches_visual_findings(&stored, expected));
    let provider_coverage_matches = matches_optional_claim(
        &stored,
        "providerCoverage",
        recomputed.report.claims.get("providerCoverage"),
    );
    if stored.get("status") != Some(&status)
        || stored.get("gaps") != Some(&json!(recomputed.report.gaps))
        || stored.pointer("/claims/lensesRan") != Some(&lenses_ran)
        || !provider_coverage_matches
        || !visual_findings_match
    {
        errors.push(
            "report.json does not match the verdict or visual findings recomputed from the ingested receipts; rerun `legion audit ingest` (reasoning lenses count as ran only via ingested receipts)"
                .into(),
        );
    }
    // A follow-up (security variant analysis) is verified by the recomputation
    // above: a signed plan bound to this run's plan digest and confirmed
    // verdicts, and a MAC'd variant receipt. One that does not chain to this
    // run is a verification failure, not a silently pending gap.
    let followup = recomputed
        .report
        .claims
        .get("securityVariantFollowup")
        .cloned()
        .unwrap_or(Value::Null);
    if followup.get("status").and_then(Value::as_str) == Some("invalid") {
        errors.push(format!(
            "security variant follow-up does not verify against this run: {}",
            followup
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unknown reason")
        ));
    }
    json!({
        "status": status,
        "securityVariantFollowup": followup,
        "gaps": recomputed.report.gaps,
        "findingCount": recomputed.report.findings.len(),
        "lensesRan": lenses_ran,
        "ingestedLenses": recomputed.ingested,
        "pendingLenses": recomputed.pending,
        "coverageNotes": recomputed.execution.coverage_notes,
        "clean": recomputed.report.status == rightkit_evidence_contracts::ReportStatus::Clean,
    })
}

/// Select the full visual finding rows so verification binds IDs, locations,
/// evidence, and display fields together. Other providers remain governed by
/// the existing verifier checks.
fn stored_visual_findings(stored: &Value) -> Option<Vec<Value>> {
    // A stored report of schema 1 or 2 compares as its v1 core (ADR-8), so the
    // v2-only fields never affect the recomputed-verdict match. A document that
    // is not a complete report keeps its raw findings.
    let findings = match rightkit_evidence_contracts::Report::read_any(stored) {
        Ok(view) => serde_json::to_value(view.v1_core().findings).ok()?,
        Err(_) => stored.get("findings")?.clone(),
    };
    Some(
        findings
            .as_array()?
            .iter()
            .filter(|finding| {
                finding.get("provider").and_then(Value::as_str) == Some("legacy.visual.core")
            })
            .cloned()
            .collect(),
    )
}

fn matches_visual_findings(stored: &Value, expected: &[Value]) -> bool {
    stored_visual_findings(stored).as_deref() == Some(expected)
}

fn matches_optional_claim(stored: &Value, name: &str, expected: Option<&Value>) -> bool {
    stored.pointer(&format!("/claims/{name}")) == expected
}
