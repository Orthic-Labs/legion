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
}

/// Plan signing key for a run: an explicit `AUDIT_PLAN_SIGNING_KEY` wins, else
/// the run's `epoch.key`. The key only verifies the plan binding (the plan is
/// re-frozen under it and must bind to the same inventory); it never re-signs
/// the stored plan.
fn verification_key(root: &std::path::Path) -> Result<Vec<u8>, CommandError> {
    if let Some(value) = std::env::var_os("AUDIT_PLAN_SIGNING_KEY").filter(|v| !v.is_empty()) {
        return Ok(value.to_string_lossy().as_bytes().to_vec());
    }
    let key_file = root.join(legion_audit::native_providers::reasoning::ingest::EPOCH_KEY_FILE);
    if !key_file.is_file() {
        return Err(CommandError::usage(format!(
            "verify needs the run's plan signing key: {} is missing and AUDIT_PLAN_SIGNING_KEY is not set",
            key_file.display()
        )));
    }
    legion_audit::native_providers::reasoning::ingest::load_epoch(root)
        .map(|(key, _)| key)
        .map_err(|error| {
            CommandError::usage(format!(
                "cannot load plan signing key {}: {error}",
                key_file.display()
            ))
        })
}

/// Verify persisted Audit artifacts and reconcile facts against its frozen plan.
/// Provider execution cryptographic checks remain owned by `legion-audit`.
pub async fn run(args: VerifyArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
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
        serde_json::from_slice(&std::fs::read(&plan_path).map_err(super::io_error)?).map_err(
            |error| CommandError::usage(format!("invalid verify plan artifact: {error}")),
        )?
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
    let facts_digest = legion_contracts::canonical_digest_hex(&facts)
        .map_err(|e| CommandError::integrity(e.to_string()))?;
    let plan_digest = legion_contracts::canonical_digest_hex(&plan)
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
    if errors.is_empty() {
        let signing_key = verification_key(&root)?;
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
                serde_json::from_value::<Vec<legion_contracts::ProviderSpec>>(specs).ok()
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
    let (status, complete) = if !errors.is_empty() {
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
    Ok(json!({
        "schemaVersion":1,
        "kind":"legion-verify",
        "status":status,
        "complete":complete,
        "repository":repository_id,
        "factsDigest":facts_digest,
        "planContentDigest":plan_digest,
        "valid":errors.is_empty(),
        "contentErrors":errors,
        "verdict":verdict,
        "runtimeCalls":runtime_calls,
        "gaps":gaps,
    }))
}

const MAX_RUNTIME_CALLS: usize = 4_096;
const MAX_RUNTIME_RECEIPT_BYTES: u64 = 256 * 1024;

fn read_runtime_call(path: &Path) -> Result<Value, String> {
    read_bounded_runtime_json(path, MAX_RUNTIME_RECEIPT_BYTES)
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
    let parent_plan =
        read_bounded_runtime_json(&parent.join("plan.json"), MAX_RUNTIME_STATE_BYTES)?;
    let child_plan = read_bounded_runtime_json(&child.join("plan.json"), MAX_RUNTIME_STATE_BYTES)?;
    let frozen: legion_audit::AuditPlan = serde_json::from_value(read_bounded_runtime_json(
        &child.join(followup::FROZEN_PLAN_FILE),
        MAX_RUNTIME_STATE_BYTES,
    )?)
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
        let plan = optional_runtime_json(&root.join("plan.json"), MAX_RUNTIME_STATE_BYTES)?;
        let frozen = optional_runtime_json(
            &root.join(followup::FROZEN_PLAN_FILE),
            MAX_RUNTIME_STATE_BYTES,
        )?;
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
                continue
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
        "clean": recomputed.report.status == legion_contracts::ReportStatus::Clean,
    })
}

/// Select the full visual finding rows so verification binds IDs, locations,
/// evidence, and display fields together. Other providers remain governed by
/// the existing verifier checks.
fn stored_visual_findings(stored: &Value) -> Option<Vec<Value>> {
    // A stored report of schema 1 or 2 compares as its v1 core (ADR-8), so the
    // v2-only fields never affect the recomputed-verdict match. A document that
    // is not a complete report keeps its raw findings.
    let findings = match legion_contracts::Report::read_any(stored) {
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

#[cfg(test)]
mod tests {
    use super::*;

    struct RuntimeFixture(PathBuf);
    impl RuntimeFixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let run = std::env::temp_dir().join(format!(
                "legion-verify-runtime-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(run.join("runtime-calls")).unwrap();
            let epoch =
                legion_audit::native_providers::reasoning::ingest::create_epoch(&run).unwrap();
            std::fs::write(run.join("plan.json"),serde_json::to_vec(&json!({"epoch":{"digest":epoch},"reviewContext":{"snapshotKey":format!("sha256:{}","1".repeat(64))}})).unwrap()).unwrap();
            Self(run)
        }
        fn receipt(&self) -> Value {
            let digest = format!("sha256:{}", "2".repeat(64));
            json!({"schemaVersion":1,"kind":"legion-runtime-call","callId":"call-one","seatId":"seat-001",
                "requestDigest":digest,"snapshotKey":format!("sha256:{}","1".repeat(64)),"requestBytes":200,
                "authorization":{"authorized":true,"callId":"call-one","reservationId":"reservation-one"},
                "observation":{"contextId":"fresh-one","processId":12,"physicalRequestDigest":digest,"physicalRequestBytes":200,
                    "usage":{"reservationId":"reservation-one","receiptId":"receipt-one","inputTokens":10,"outputTokens":2,"cachedInputTokens":0,"retryTokens":0,"failed":false,"rawPrompt":"DO_NOT_PROJECT"},
                    "rawUsage":{"rawResponse":"DO_NOT_PROJECT"},"reportedApiEquivalentCostUsd":"0.1234567890123456789","observedModels":["sonnet"],"modelPolicyViolation":null},
                "modelAction":{"kind":"toolRequest","toolRequest":{"tool":"audit.search_code","arguments":{"query":"DO_NOT_PROJECT"}}}})
        }
        fn seal_plan(&self, parent_digest: Option<&str>) -> String {
            let mut outer =
                read_bounded_runtime_json(&self.0.join("plan.json"), MAX_RUNTIME_STATE_BYTES)
                    .unwrap();
            let mut bounds = json!({});
            if let Some(parent) = parent_digest {
                bounds["followup"] = json!({"parentPlanDigest":parent});
                outer["followupOf"] =
                    json!({"kind":"security-variant-analysis","parentPlanDigest":parent});
            }
            let plan: legion_audit::AuditPlan = serde_json::from_value(json!({
                "schemaVersion":1,"repositoryId":"fixture","inventoryGeneration":"revision",
                "inventoryDigest":format!("sha256:{}","3".repeat(64)),"providers":[],"bounds":bounds
            }))
            .unwrap();
            let key = if parent_digest.is_some() {
                legion_audit::native_providers::reasoning::ingest::load_epoch(&self.0)
                    .unwrap()
                    .0
            } else {
                verification_key(&self.0).unwrap()
            };
            let digest = legion_audit::plan_digest(&plan).unwrap();
            let signature = legion_audit::sign(&plan, &key).unwrap();
            outer["seal"] = json!({"digest":digest,"signature":signature});
            outer["nativePlan"] =
                json!({"schemaVersion":1,"digest":digest,"signature":signature,"plan":plan});
            std::fs::write(
                self.0.join("plan.json"),
                serde_json::to_vec(&outer).unwrap(),
            )
            .unwrap();
            if parent_digest.is_some() {
                std::fs::write(
                    self.0.join("frozen-plan.json"),
                    serde_json::to_vec(&plan).unwrap(),
                )
                .unwrap();
            }
            digest
        }
        fn write(&self, name: &str, receipt: &Value) {
            let state_path = self.0.join(legion_audit::next::STATE_FILE);
            let mut state = optional_runtime_json(&state_path,16 * 1024 * 1024).unwrap().unwrap_or_else(|| json!({"schemaVersion":2,"kind":"legion-audit-next-state","reservations":{}}));
            let mut usage = receipt["observation"]["usage"].clone();
            usage.as_object_mut().unwrap().remove("rawPrompt");
            state["reservations"][receipt["authorization"]["reservationId"].as_str().unwrap()] = json!({"callId":receipt["callId"],"transportAuthorized":true,"nativeCostRequired":true,"usage":usage,"reportedApiCostUsd":receipt["observation"]["reportedApiEquivalentCostUsd"]});
            std::fs::write(state_path, serde_json::to_vec(&state).unwrap()).unwrap();
            let minted = legion_audit::native_providers::reasoning::ingest::mint_runtime_call(
                &self.0, receipt,
            )
            .unwrap();
            std::fs::write(
                self.0.join("runtime-calls").join(name),
                serde_json::to_vec(&minted).unwrap(),
            )
            .unwrap();
        }
    }
    impl Drop for RuntimeFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Freeze an owner-bound lineage with real MAC receipts, without copying
    /// parent receipts into child or invoking continuation's model runner.
    struct ContinuationFixture {
        parent: RuntimeFixture,
        child: RuntimeFixture,
    }
    impl ContinuationFixture {
        fn new() -> Self {
            fn hash(path: &Path) -> String {
                use sha2::Digest;
                hex::encode(sha2::Sha256::digest(std::fs::read(path).unwrap()))
            }
            fn parent_files(root: &Path, dir: &Path, files: &mut BTreeMap<String, String>) {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    let name = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/");
                    if name == "epoch.key" {
                        continue;
                    }
                    if path.is_dir() {
                        parent_files(root, &path, files);
                    } else {
                        files.insert(name, hash(&path));
                    }
                }
            }
            fn put(path: &Path, value: &Value) {
                std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
            }
            let parent = RuntimeFixture::new();
            let child = RuntimeFixture::new();
            parent.write("parent.json", &parent.receipt());
            let state_file = legion_audit::next::STATE_FILE;
            let mut inherited =
                read_bounded_runtime_json(&parent.0.join(state_file), MAX_RUNTIME_STATE_BYTES)
                    .unwrap();
            inherited["issuances"] = json!(1);
            inherited["adjudicationRound"] = json!(0);
            inherited["spent"] = json!({"judgment":11227});
            inherited["leases"] = json!({});
            inherited["terminalStatus"] = json!("incomplete:budget-overrun");
            put(&parent.0.join(state_file), &inherited);
            for name in ["plan.json", "epoch.key"] {
                std::fs::copy(parent.0.join(name), child.0.join(name)).unwrap();
            }
            put(
                &child.0.join(legion_audit::next::DISPATCH_FILE),
                &json!({
                    "continuationRecipe":{"schemaVersion":1,"kind":"frozen-source-rematerialization","modelsStarted":0},
                    "reasoningBudget":{"schemaVersion":2,"totalTokens":50000,"perCallTokens":10000,"maxSeats":5,"outputTokens":2500},
                    "limits":{"waveWidth":1},"seats":[]
                }),
            );
            let mut frozen_parent = BTreeMap::new();
            parent_files(&parent.0, &parent.0, &mut frozen_parent);
            let child_recipe = ["plan.json", legion_audit::next::DISPATCH_FILE]
                .into_iter()
                .map(|name| (name, hash(&child.0.join(name))))
                .collect::<BTreeMap<_, _>>();
            let manifest_path = child.0.join(legion_audit::continuation::CONTINUATION_FILE);
            put(
                &manifest_path,
                &json!({"schemaVersion":1,"kind":"legion-audit-continuation",
                "parent":std::fs::canonicalize(&parent.0).unwrap(),"child":std::fs::canonicalize(&child.0).unwrap(),
                "operatorInstruction":"resume within original cumulative budget","parentFiles":frozen_parent,
                "childRecipe":child_recipe,"inheritedState":inherited}),
            );
            let manifest_digest = hash(&manifest_path);
            put(
                &parent.0.join("continuation-active.json"),
                &json!({"schemaVersion":1,
                "kind":"legion-audit-continuation-owner","child":std::fs::canonicalize(&child.0).unwrap(),
                "manifestDigest":manifest_digest}),
            );
            let mut state = inherited;
            state["terminalStatus"] = Value::Null;
            state["historicalTerminalStatus"] = json!("incomplete:budget-overrun");
            state["continuationDigest"] = json!(manifest_digest);
            state["dispatchDigest"] = json!(hash(&child.0.join(legion_audit::next::DISPATCH_FILE)));
            put(&child.0.join(state_file), &state);
            let mut receipt = child.receipt();
            receipt["callId"] = json!("child-call");
            receipt["authorization"]["callId"] = json!("child-call");
            receipt["authorization"]["reservationId"] = json!("child-reservation");
            receipt["observation"]["usage"]["reservationId"] = json!("child-reservation");
            receipt["observation"]["usage"]["receiptId"] = json!("child-receipt");
            child.write("child.json", &receipt);
            assert!(legion_audit::continuation::validate_lineage(&child.0)
                .unwrap()
                .is_some());
            Self { parent, child }
        }
    }

    #[test]
    fn continuation_verifies_immutable_parent_and_new_child_calls_once_from_either_run() {
        let fixture = ContinuationFixture::new();
        let parent_state =
            std::fs::read(fixture.parent.0.join(legion_audit::next::STATE_FILE)).unwrap();
        for run in [&fixture.parent.0, &fixture.child.0] {
            let mut errors = Vec::new();
            let projected = runtime_calls(run, &mut errors);
            assert!(errors.is_empty(), "{errors:?}");
            assert_eq!(projected["status"], "verified");
            assert_eq!(projected["count"], 2);
            assert_eq!(projected["receiptCount"], 2);
            assert_eq!(projected["nativeReservationCount"], 2);
            assert_eq!(
                projected["accountingRoot"],
                json!(std::fs::canonicalize(&fixture.parent.0).unwrap())
            );
        }
        assert_eq!(
            std::fs::read(fixture.parent.0.join(legion_audit::next::STATE_FILE)).unwrap(),
            parent_state
        );
        assert!(!fixture.child.0.join("runtime-calls/parent.json").exists());
        std::fs::copy(
            fixture.parent.0.join("runtime-calls/parent.json"),
            fixture.child.0.join("runtime-calls/duplicate.json"),
        )
        .unwrap();
        let mut errors = Vec::new();
        assert_eq!(
            runtime_calls(&fixture.child.0, &mut errors)["status"],
            "invalid"
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate runtime")));
    }

    #[test]
    fn continuation_accounting_rejects_missing_ancestry_state_forks_and_inherited_charge_tampering()
    {
        for mutation in ["manifest", "state", "fork", "reservation", "spend"] {
            let fixture = ContinuationFixture::new();
            let state_path = fixture.child.0.join(legion_audit::next::STATE_FILE);
            match mutation {
                "manifest" => std::fs::remove_file(
                    fixture
                        .child
                        .0
                        .join(legion_audit::continuation::CONTINUATION_FILE),
                )
                .unwrap(),
                "state" => std::fs::remove_file(&state_path).unwrap(),
                "fork" => {
                    let owner_path = fixture.parent.0.join("continuation-active.json");
                    let mut owner =
                        read_bounded_runtime_json(&owner_path, MAX_RUNTIME_STATE_BYTES).unwrap();
                    owner["child"] = json!(fixture.parent.0);
                    std::fs::write(owner_path, serde_json::to_vec(&owner).unwrap()).unwrap();
                }
                _ => {
                    let mut state =
                        read_bounded_runtime_json(&state_path, MAX_RUNTIME_STATE_BYTES).unwrap();
                    if mutation == "reservation" {
                        state["reservations"]["reservation-one"]["reportedApiCostUsd"] = json!("0");
                    } else {
                        state["spent"]["judgment"] = json!(0);
                    }
                    std::fs::write(state_path, serde_json::to_vec(&state).unwrap()).unwrap();
                }
            }
            for run in [&fixture.parent.0, &fixture.child.0] {
                let mut errors = Vec::new();
                assert_eq!(
                    runtime_calls(run, &mut errors)["status"],
                    "invalid",
                    "{mutation}: {errors:?}"
                );
                assert!(!errors.is_empty());
            }
        }
    }

    #[test]
    fn runtime_calls_authenticate_exact_cost_and_project_no_raw_content() {
        let fixture = RuntimeFixture::new();
        fixture.write("one.json", &fixture.receipt());
        let mut errors = Vec::new();
        let projected = runtime_calls(&fixture.0, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(projected["status"], "verified");
        assert_eq!(projected["count"], 1);
        assert_eq!(
            projected["calls"][0]["reportedApiEquivalentCostUsd"],
            "0.1234567890123456789"
        );
        assert_eq!(projected["calls"][0]["usage"]["inputTokens"], 10);
        assert_eq!(
            projected["calls"][0]["processIdentity"]["contextId"],
            "fresh-one"
        );
        assert!(!projected.to_string().contains("DO_NOT_PROJECT"));
        let path = fixture.0.join("runtime-calls/one.json");
        let duplicate = fixture.0.join("runtime-calls/duplicate.json");
        std::fs::copy(&path, &duplicate).unwrap();
        errors.clear();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate runtime callId")));
        std::fs::remove_file(duplicate).unwrap();
        let mut tampered = read_runtime_call(&path).unwrap();
        tampered["observation"]["usage"]["inputTokens"] = json!(999);
        std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        errors.clear();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(!errors.is_empty());
    }

    #[test]
    fn runtime_call_duplicate_identities_and_mismatched_reservations_are_rejected() {
        let fixture = RuntimeFixture::new();
        let first = fixture.receipt();
        for identity in ["call", "receipt", "reservation"] {
            let mut ids = RuntimeCallIds::default();
            ids.record(&first).unwrap();
            let mut other = first.clone();
            other["callId"] = json!(if identity == "call" {
                "call-one"
            } else {
                "call-two"
            });
            other["observation"]["usage"]["receiptId"] = json!(if identity == "receipt" {
                "receipt-one"
            } else {
                "receipt-two"
            });
            let reservation = if identity == "reservation" {
                "reservation-one"
            } else {
                "reservation-two"
            };
            other["authorization"]["reservationId"] = json!(reservation);
            other["observation"]["usage"]["reservationId"] = json!(reservation);
            assert!(ids.record(&other).unwrap_err().contains("duplicate"));
        }
        let mut mismatched = first;
        mismatched["observation"]["usage"]["reservationId"] = json!("unbound");
        assert!(RuntimeCallIds::default().record(&mismatched).is_err());
    }

    #[test]
    fn runtime_call_file_limits_and_absent_calls_fail_closed_without_execution() {
        let fixture = RuntimeFixture::new();
        let mut errors = Vec::new();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "not-run");
        std::fs::remove_dir(fixture.0.join("runtime-calls")).unwrap();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "not-run");
        assert!(errors.is_empty());
        std::fs::create_dir(fixture.0.join("runtime-calls")).unwrap();
        let path = fixture.0.join("runtime-calls/invalid.json");
        std::fs::write(&path, b"{").unwrap();
        assert!(read_runtime_call(&path).is_err());
        std::fs::write(&path, vec![b' '; MAX_RUNTIME_RECEIPT_BYTES as usize + 1]).unwrap();
        assert!(read_runtime_call(&path).is_err());
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(!errors.is_empty());
    }

    #[test]
    fn runtime_accounting_rejects_missing_receipts_directories_and_state() {
        let fixture = RuntimeFixture::new();
        fixture.write("one.json", &fixture.receipt());
        let mut second = fixture.receipt();
        second["callId"] = json!("call-two");
        second["authorization"]["callId"] = json!("call-two");
        second["authorization"]["reservationId"] = json!("reservation-two");
        second["observation"]["usage"]["reservationId"] = json!("reservation-two");
        second["observation"]["usage"]["receiptId"] = json!("receipt-two");
        fixture.write("two.json", &second);
        std::fs::remove_file(fixture.0.join("runtime-calls/two.json")).unwrap();
        let mut errors = Vec::new();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(errors
            .iter()
            .any(|error| error.contains("missing matching")));
        std::fs::remove_dir_all(fixture.0.join("runtime-calls")).unwrap();
        errors.clear();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(errors
            .iter()
            .any(|error| error.contains("missing matching")));
        std::fs::create_dir(fixture.0.join("runtime-calls")).unwrap();
        fixture.write("one.json", &fixture.receipt());
        std::fs::remove_file(fixture.0.join(legion_audit::next::STATE_FILE)).unwrap();
        errors.clear();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(errors.iter().any(|error| error.contains("no persisted")));
        std::fs::remove_dir_all(fixture.0.join("runtime-calls")).unwrap();
        std::fs::write(
            fixture.0.join("review-runtime.json"),
            serde_json::to_vec(&json!({"kind":"legion-audit-runtime","calls":1})).unwrap(),
        )
        .unwrap();
        errors.clear();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(errors
            .iter()
            .any(|error| error.contains("physical call count")));
    }

    #[test]
    fn runtime_accounting_matches_call_usage_and_exact_cost_and_summary_count() {
        let fixture = RuntimeFixture::new();
        fixture.write("one.json", &fixture.receipt());
        let state_path = fixture.0.join(legion_audit::next::STATE_FILE);
        let original = read_bounded_runtime_json(&state_path, MAX_RUNTIME_STATE_BYTES).unwrap();
        for (field, value) in [
            ("callId", json!("different")),
            (
                "usage",
                json!({"reservationId":"reservation-one","receiptId":"receipt-one","inputTokens":11,"outputTokens":2,"cachedInputTokens":0,"retryTokens":0,"failed":false}),
            ),
            ("reportedApiCostUsd", json!("0.1234567890123456788")),
        ] {
            let mut modified = original.clone();
            modified["reservations"]["reservation-one"][field] = value;
            std::fs::write(&state_path, serde_json::to_vec(&modified).unwrap()).unwrap();
            let mut errors = Vec::new();
            assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
            assert!(errors
                .iter()
                .any(|error| error.contains("differs from persisted")));
        }
        std::fs::write(&state_path, serde_json::to_vec(&original).unwrap()).unwrap();
        for (count, status) in [(0, "verified"), (1, "verified"), (2, "invalid")] {
            std::fs::write(
                fixture.0.join("review-runtime.json"),
                serde_json::to_vec(&json!({"kind":"legion-audit-runtime","calls":count})).unwrap(),
            )
            .unwrap();
            let mut errors = Vec::new();
            assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], status);
        }
    }

    #[test]
    fn runtime_followup_authenticates_child_epoch_and_parent_budget_once() {
        let parent = RuntimeFixture::new();
        let mut child = RuntimeFixture::new();
        let child_path = parent.0.join("followup");
        std::fs::rename(&child.0, &child_path).unwrap();
        child.0 = child_path;
        let parent_digest = parent.seal_plan(None);
        child.seal_plan(Some(&parent_digest));
        parent.write("one.json", &parent.receipt());
        let mut receipt = child.receipt();
        receipt["callId"] = json!("child-call");
        receipt["authorization"]["callId"] = json!("child-call");
        receipt["authorization"]["reservationId"] = json!("child-reservation");
        receipt["observation"]["usage"]["reservationId"] = json!("child-reservation");
        receipt["observation"]["usage"]["receiptId"] = json!("child-receipt");
        child.write("child.json", &receipt);
        let parent_state_path = parent.0.join(legion_audit::next::STATE_FILE);
        let child_state_path = child.0.join(legion_audit::next::STATE_FILE);
        let mut parent_state =
            read_bounded_runtime_json(&parent_state_path, MAX_RUNTIME_STATE_BYTES).unwrap();
        let child_state =
            read_bounded_runtime_json(&child_state_path, MAX_RUNTIME_STATE_BYTES).unwrap();
        parent_state["reservations"]["child-reservation"] =
            child_state["reservations"]["child-reservation"].clone();
        std::fs::write(
            parent_state_path,
            serde_json::to_vec(&parent_state).unwrap(),
        )
        .unwrap();
        let mut duplicate_errors = Vec::new();
        assert_eq!(
            runtime_calls(&parent.0, &mut duplicate_errors)["status"],
            "invalid"
        );
        assert!(duplicate_errors
            .iter()
            .any(|error| error.contains("lacks validated inheritance")));
        std::fs::remove_file(child_state_path).unwrap();
        for run in [&parent.0, &child.0] {
            let mut errors = Vec::new();
            let projected = runtime_calls(run, &mut errors);
            assert!(errors.is_empty(), "{errors:?}");
            assert_eq!(projected["status"], "verified");
            assert_eq!(projected["count"], 2);
            assert_eq!(projected["nativeReservationCount"], 2);
        }
        std::fs::remove_file(child.0.join("runtime-calls/child.json")).unwrap();
        let mut errors = Vec::new();
        assert_eq!(runtime_calls(&parent.0, &mut errors)["status"], "invalid");
        assert!(errors
            .iter()
            .any(|error| error.contains("missing matching")));
        let mut frozen =
            read_bounded_runtime_json(&child.0.join("frozen-plan.json"), MAX_RUNTIME_STATE_BYTES)
                .unwrap();
        frozen["bounds"]["followup"]["parentPlanDigest"] = json!("different-parent");
        std::fs::write(
            child.0.join("frozen-plan.json"),
            serde_json::to_vec(&frozen).unwrap(),
        )
        .unwrap();
        errors.clear();
        assert_eq!(runtime_calls(&parent.0, &mut errors)["status"], "invalid");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_call_symlink_files_are_rejected() {
        let fixture = RuntimeFixture::new();
        fixture.write("one.json", &fixture.receipt());
        let link = fixture.0.join("runtime-calls/link.json");
        std::os::unix::fs::symlink("one.json", &link).unwrap();
        assert!(read_runtime_call(&link).is_err());
        let mut errors = Vec::new();
        assert_eq!(runtime_calls(&fixture.0, &mut errors)["status"], "invalid");
        assert!(!errors.is_empty());
    }

    fn finding(provider: &str) -> Value {
        json!({
            "id": "finding-visual-1",
            "severity": "medium",
            "title": "Screenshot differs",
            "message": "Rendered pixels differ from baseline",
            "provider": provider,
            "locations": [],
            "evidence": {
                "kind": "visual-artifact-difference",
                "actual": {"path": "actual.png", "sha256": "a1", "size": 12},
                "baseline": {"path": "baseline.png", "sha256": "b2", "size": 11}
            }
        })
    }

    #[test]
    fn visual_finding_subset_requires_exact_rows_and_catches_deletion() {
        let expected = finding("legacy.visual.core");
        let stored = json!({"findings": [expected.clone(), finding("legacy.code.core")]});
        assert!(matches_visual_findings(
            &stored,
            std::slice::from_ref(&expected)
        ));

        let deleted = json!({"findings": [finding("legacy.code.core")]});
        assert!(!matches_visual_findings(
            &deleted,
            std::slice::from_ref(&expected)
        ));

        for field in [
            "id",
            "severity",
            "title",
            "message",
            "locations",
            "evidence",
        ] {
            let mut tampered = expected.clone();
            tampered[field] = json!("tampered");
            let report = json!({"findings": [tampered]});
            assert!(!matches_visual_findings(
                &report,
                std::slice::from_ref(&expected)
            ));
        }
    }

    #[test]
    fn visual_subset_handles_zero_findings_without_validating_other_providers() {
        let no_visual = json!({"findings": [finding("legacy.code.core")]});
        assert!(matches_visual_findings(&no_visual, &[]));
        assert!(!matches_visual_findings(&json!({}), &[]));
    }

    #[test]
    fn provider_coverage_claim_must_match_recomputed_presence_and_contents() {
        let coverage = json!({"fullScope": false, "planComplete": false});
        let recomputed = Some(&coverage);
        assert!(matches_optional_claim(
            &json!({"claims": {"providerCoverage": coverage}}),
            "providerCoverage",
            recomputed,
        ));
        assert!(!matches_optional_claim(
            &json!({"claims": {}}),
            "providerCoverage",
            recomputed,
        ));
        assert!(!matches_optional_claim(
            &json!({"claims": {"providerCoverage": {"fullScope": true}}}),
            "providerCoverage",
            recomputed,
        ));
        assert!(matches_optional_claim(
            &json!({"claims": {}}),
            "providerCoverage",
            None,
        ));
        assert!(!matches_optional_claim(
            &json!({"claims": {"providerCoverage": {"fullScope": true}}}),
            "providerCoverage",
            None,
        ));
    }
}
