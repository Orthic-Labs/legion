//! Explicit, single-child continuation of a stopped Audit budget.
//!
//! This is a linked ledger, never a fresh budget. Parent artifacts stay byte
//! identical; only a separate root ownership record & advisory lock are added.
use crate::{
    next::{StateLock, DISPATCH_FILE, STATE_FILE},
    AuditError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const CONTINUATION_FILE: &str = "continuation.json";
/// Signed plan-generation chain recorded beside the child's frozen plan when
/// the continuation raises an engagement budget (never replaces plan.json,
/// which must stay byte-equal to the parent's frozen foundation).
pub const PLAN_CHAIN_FILE: &str = "plan-amendments.json";
const ACTIVE_FILE: &str = "continuation-active.json";
const KIND: &str = "legion-audit-continuation";
const STOP: &str = "incomplete:budget-overrun";
const FOUNDATION: &[&str] = &[
    "plan.json",
    "facts.json",
    "execution.json",
    "inventory.json",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    kind: String,
    parent: PathBuf,
    child: PathBuf,
    operator_instruction: String,
    parent_files: BTreeMap<String, String>,
    child_recipe: BTreeMap<String, String>,
    inherited_state: Value,
    /// Present when the continuation produced a signed ExtendBudget plan
    /// generation; binds the chain file to this manifest digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plan_generation: Option<Value>,
}

fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(path: &Path) -> Result<Vec<u8>, AuditError> {
    fs::read(path).map_err(|e| invalid(format!("continuation cannot read {}: {e}", path.display())))
}
fn json_file(path: &Path) -> Result<Value, AuditError> {
    serde_json::from_slice(&read(path)?)
        .map_err(|e| invalid(format!("invalid continuation JSON {}: {e}", path.display())))
}
fn canonical(path: &Path) -> Result<PathBuf, AuditError> {
    fs::canonicalize(path)
        .map_err(|e| invalid(format!("continuation path {}: {e}", path.display())))
}
fn write_new(path: &Path, value: &impl Serialize) -> Result<(), AuditError> {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| invalid(e.to_string()))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            invalid(format!(
                "continuation cannot create {}: {e}",
                path.display()
            ))
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| invalid(e.to_string()))
}

/// Resolve before locking, then validate again under that same root lock.
/// Never acquire a child lock followed by its root lock.
pub(crate) fn lock_root(run: &Path) -> Result<PathBuf, AuditError> {
    let manifest_path = run.join(CONTINUATION_FILE);
    if manifest_path.exists() {
        let manifest: Manifest = serde_json::from_slice(&read(&manifest_path)?)
            .map_err(|e| invalid(format!("invalid continuation manifest: {e}")))?;
        if manifest.schema_version != 1
            || manifest.kind != KIND
            || canonical(run)? != manifest.child
        {
            return Err(invalid("continuation identity/schema mismatch"));
        }
        return canonical(&manifest.parent);
    }
    if run.join(STATE_FILE).exists()
        && json_file(&run.join(STATE_FILE))?["continuationDigest"].is_string()
    {
        return Err(invalid(
            "continuation ancestry missing; budget cannot reset",
        ));
    }
    if run.join(DISPATCH_FILE).exists()
        && json_file(&run.join(DISPATCH_FILE))?
            .get("continuationRecipe")
            .is_some()
    {
        return Err(invalid(
            "continuation recipe has no linked ancestry; fresh budget refused",
        ));
    }
    Ok(run.to_path_buf())
}

fn collect_files(root: &Path, recipe: bool) -> Result<BTreeMap<String, String>, AuditError> {
    fn visit(
        root: &Path,
        dir: &Path,
        recipe: bool,
        out: &mut BTreeMap<String, String>,
    ) -> Result<(), AuditError> {
        for entry in fs::read_dir(dir).map_err(|e| invalid(e.to_string()))? {
            let entry = entry.map_err(|e| invalid(e.to_string()))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|e| invalid(e.to_string()))?;
            let name = relative
                .to_str()
                .ok_or_else(|| invalid("non-UTF8 continuation artifact"))?
                .replace('\\', "/");
            // Epoch material remains opaque; its public digest is sealed in plan.json.
            if matches!(
                name.as_str(),
                "epoch.key"
                    | ".next-state.lock"
                    | "review-runtime.lock"
                    | ACTIVE_FILE
                    | CONTINUATION_FILE
            ) {
                continue;
            }
            let top = name.split('/').next().unwrap_or("");
            if recipe
                && !(FOUNDATION.contains(&top)
                    || top == DISPATCH_FILE
                    || top == "lens-packets"
                    || top == "candidate-routing.json"
                    || top.starts_with("promotion."))
            {
                continue;
            }
            let kind = entry.file_type().map_err(|e| invalid(e.to_string()))?;
            if kind.is_symlink() {
                return Err(invalid(format!(
                    "continuation refuses symlink artifact {name}"
                )));
            }
            if kind.is_dir() {
                visit(root, &path, recipe, out)?;
            } else if kind.is_file() {
                out.insert(name, hash(&read(&path)?));
            } else {
                return Err(invalid("continuation refuses non-file artifact"));
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(root, root, recipe, &mut files)?;
    Ok(files)
}
fn require_files(root: &Path, files: &BTreeMap<String, String>) -> Result<(), AuditError> {
    for (name, digest) in files {
        if hash(&read(&root.join(name))?) != *digest {
            return Err(invalid(format!(
                "continuation immutable artifact changed: {}",
                root.join(name).display()
            )));
        }
    }
    Ok(())
}
fn checked_u64(value: &Value, name: &str) -> Result<u64, AuditError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("continuation missing {name}")))
}
fn remaining(parent: &Path, state: &Value) -> Result<Value, AuditError> {
    let dispatch = json_file(&parent.join(DISPATCH_FILE))?;
    let budget = &dispatch["reasoningBudget"];
    if budget["schemaVersion"] != 2 {
        return Err(invalid(
            "continuation requires version 2 frozen reasoning budget",
        ));
    }
    let charged = state["spent"]
        .as_object()
        .ok_or_else(|| invalid("missing inherited spend"))?
        .values()
        .try_fold(0u64, |sum, value| {
            sum.checked_add(
                value
                    .as_u64()
                    .ok_or_else(|| invalid("malformed inherited spend"))?,
            )
            .ok_or_else(|| invalid("inherited spend overflow"))
        })?;
    let total = checked_u64(budget, "totalTokens")?;
    let calls = checked_u64(budget, "maxSeats")?;
    let per_call = checked_u64(budget, "perCallTokens")?;
    if per_call == 0 {
        return Err(invalid("continuation per-call allowance must be positive"));
    }
    let remaining_tokens = total.saturating_sub(charged);
    let remaining_calls = calls
        .saturating_sub(checked_u64(state, "issuances")?)
        .min(remaining_tokens / per_call);
    Ok(
        json!({"remainingTokens":remaining_tokens, "remainingCalls":remaining_calls,
        "perCallTokens":per_call,"outputTokens":checked_u64(budget,"outputTokens")?,
        "waveWidth":dispatch.pointer("/limits/waveWidth").and_then(Value::as_u64).unwrap_or(crate::next::DEFAULT_WAVE_WIDTH),
        "originalReasoningBudget":budget}),
    )
}

fn authenticate_parent(parent: &Path, state: &Value) -> Result<(), AuditError> {
    let plan = json_file(&parent.join("plan.json"))?;
    let manifest = plan
        .pointer("/reviewContext/snapshotManifest")
        .or_else(|| plan.pointer("/metadata/reviewContext/snapshotManifest"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("continuation frozen source snapshot missing"))?;
    crate::snapshot::FrozenSnapshot::open(Path::new(manifest))?.verify_source_current()?;
    let mut authenticated = BTreeMap::new();
    let expected_summary = crate::next::continuation_summary(state)?;
    let mut final_summary_authenticated = false;
    for (index, entry) in fs::read_dir(parent.join("runtime-calls"))
        .map_err(|e| {
            invalid(format!(
                "continuation authenticated call evidence missing: {e}"
            ))
        })?
        .enumerate()
    {
        if index >= 4096 {
            return Err(invalid("continuation parent call evidence exceeds bound"));
        }
        let path = entry.map_err(|e| invalid(e.to_string()))?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let envelope = json_file(&path)?;
        let receipt =
            crate::native_providers::reasoning::ingest::verify_runtime_call(parent, &envelope)?;
        // Original protocol sealed reconciliation's cumulative economics even
        // before individual tier/retry fields were exposed on authorization.
        // At least one authenticated receipt must witness this final ledger.
        let summary = &receipt["budget"]["budget"];
        if [
            "plannedTokens",
            "reservedTokens",
            "chargedByTier",
            "actual",
            "unknownUsageCalls",
            "legacyUnknownUsageCalls",
            "retryCalls",
            "failedCalls",
            "actualOverrunTokens",
            "outputCapOverrunTokens",
            "cost",
            "terminalStatus",
        ]
        .iter()
        .all(|field| summary.get(*field) == expected_summary.get(*field))
        {
            final_summary_authenticated = true;
        }
        let id = receipt
            .pointer("/authorization/reservationId")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("authenticated parent reservation missing"))?
            .to_owned();
        if authenticated.insert(id, receipt).is_some() {
            return Err(invalid("duplicate parent reservation authentication"));
        }
    }
    for (id, reservation) in state["reservations"]
        .as_object()
        .ok_or_else(|| invalid("parent reservations missing"))?
    {
        let receipt = authenticated
            .remove(id)
            .ok_or_else(|| invalid("parent reservation lacks authenticated runtime call"))?;
        if receipt["callId"] != reservation["callId"]
            || receipt["authorization"]["reservedTokens"] != reservation["reservedTokens"]
            || receipt["authorization"]["outputTokenLimit"] != reservation["outputTokenLimit"]
            || receipt.pointer("/observation/usage") != Some(&reservation["usage"])
            || receipt.pointer("/observation/reportedApiEquivalentCostUsd")
                != Some(&reservation["reportedApiCostUsd"])
        {
            return Err(invalid(
                "parent ledger does not match authenticated usage/cost",
            ));
        }
        for field in ["tier", "retry", "plannedTokens"] {
            if receipt["authorization"]
                .get(field)
                .is_some_and(|value| value != &reservation[field])
            {
                return Err(invalid(
                    "parent reservation disagrees with authenticated authorization",
                ));
            }
        }
    }
    if !authenticated.is_empty() {
        return Err(invalid(
            "authenticated parent calls missing from cumulative ledger",
        ));
    }
    if !final_summary_authenticated {
        return Err(invalid("parent cumulative charge/retry/failure/usage/cost lacks authenticated final reconciliation"));
    }
    Ok(())
}

/// Planning allowances only. Final preparation rechecks under the root lock.
pub fn planning_budget(parent: &Path) -> Result<Value, AuditError> {
    let _lock = StateLock::acquire(parent)?;
    let state = crate::next::continuation_parent_state(parent)?;
    remaining(parent, &state)
}

/// Bind an already staged new recipe to immutable original evidence & ledger.
/// Only the first explicit resume is supported; siblings & nested resumes fail.
pub fn prepare(
    parent: &Path,
    child: &Path,
    operator_instruction: &str,
) -> Result<Value, AuditError> {
    if operator_instruction.trim().is_empty() {
        return Err(invalid("explicit operator resume instruction required"));
    }
    let parent = canonical(parent)?;
    let child = canonical(child)?;
    if parent == child
        || child.starts_with(&parent)
        || parent.starts_with(&child)
        || parent.join(CONTINUATION_FILE).exists()
    {
        return Err(invalid(
            "continuation requires separate original parent & child directories",
        ));
    }
    let _lock = StateLock::acquire(&parent)?;
    let active_path = parent.join(ACTIVE_FILE);
    if active_path.exists() {
        let active = json_file(&active_path)?;
        if active["child"] != json!(child) {
            return Err(invalid(
                "continuation sibling fork refused; root already owns a child",
            ));
        }
        let manifest: Manifest = serde_json::from_slice(&read(&child.join(CONTINUATION_FILE))?)
            .map_err(|e| invalid(e.to_string()))?;
        if manifest.parent != parent
            || manifest.child != child
            || manifest.operator_instruction != operator_instruction
        {
            return Err(invalid(
                "continuation replay conflicts with frozen resume event",
            ));
        }
        // Missing state might be a deleted spent ledger. Never reconstruct it
        // from the initial seed, even after an interrupted preparation.
        return validate_lineage(&child)?.ok_or_else(|| invalid("continuation ancestry missing"));
    }
    if child.join(STATE_FILE).exists() || child.join(CONTINUATION_FILE).exists() {
        return Err(invalid(
            "continuation child already contains unbound accounting/ancestry",
        ));
    }
    let state = crate::next::continuation_parent_state(&parent)?;
    if json_file(&parent.join(STATE_FILE))? != state {
        return Err(invalid("continuation requires exact current-schema parent ledger; migration cannot rewrite historical state"));
    }
    authenticate_parent(&parent, &state)?;
    let allowance = remaining(&parent, &state)?;
    let original_dispatch = json_file(&parent.join(DISPATCH_FILE))?;
    let dispatch = json_file(&child.join(DISPATCH_FILE))?;
    if dispatch["reasoningBudget"] != original_dispatch["reasoningBudget"]
        || dispatch.pointer("/limits/waveWidth") != original_dispatch.pointer("/limits/waveWidth")
    {
        return Err(invalid(
            "continuation changed original budget ceilings or width",
        ));
    }
    for file in FOUNDATION {
        if read(&parent.join(file))? != read(&child.join(file))? {
            return Err(invalid(format!(
                "continuation changed frozen foundation {file}"
            )));
        }
    }
    let seats = dispatch["seats"]
        .as_array()
        .ok_or_else(|| invalid("continuation recipe seats missing"))?;
    let leases = state["leases"]
        .as_object()
        .ok_or_else(|| invalid("inherited attempts missing"))?;
    let mut new_ids = std::collections::BTreeSet::new();
    let mut calls = u64::from(!seats.is_empty()); // permanent fresh verifier reserve
    for seat in seats {
        let id = seat["seatId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid("continuation seats require explicit fresh IDs"))?;
        if leases.contains_key(id) || !new_ids.insert(id) {
            return Err(invalid(
                "continuation seat identity collides with retained attempts",
            ));
        }
        if !matches!(
            seat["gatherPolicy"].as_str(),
            Some("deterministic" | "deterministic-zero-call") | None
        ) {
            return Err(invalid("continuation requires deterministic gathering"));
        }
        calls = calls
            .checked_add(1)
            .ok_or_else(|| invalid("continuation call overflow"))?;
    }
    if calls == 0
        || calls > checked_u64(&allowance, "remainingCalls")?
        || calls.saturating_mul(checked_u64(&allowance, "perCallTokens")?)
            > checked_u64(&allowance, "remainingTokens")?
    {
        return Err(invalid(
            "continuation recipe does not fit cumulative charge plus fresh verifier reserve",
        ));
    }
    // Receipt-backed packets/evidence cannot be silently rewritten by replanning.
    if parent.join("lens-receipts").exists() {
        for entry in
            fs::read_dir(parent.join("lens-receipts")).map_err(|e| invalid(e.to_string()))?
        {
            let entry = entry.map_err(|e| invalid(e.to_string()))?;
            if entry.path().extension().is_some_and(|ext| ext == "json") {
                let name = entry.file_name();
                for dir in ["lens-receipts", "lens-packets"] {
                    if read(&parent.join(dir).join(&name))? != read(&child.join(dir).join(&name))? {
                        return Err(invalid(
                            "continuation changed accepted packet/receipt evidence",
                        ));
                    }
                }
            }
        }
    }
    // Signed ExtendBudget generation (engagement plans only). Computed before
    // anything is written so a refused amendment leaves the child untouched.
    let generation = plan_generation(&child, operator_instruction, None)?;
    let manifest = Manifest {
        schema_version: 1,
        kind: KIND.into(),
        parent: parent.clone(),
        child: child.clone(),
        operator_instruction: operator_instruction.into(),
        parent_files: collect_files(&parent, false)?,
        child_recipe: collect_files(&child, true)?,
        inherited_state: state,
        plan_generation: generation.as_ref().map(|(_, _, summary)| summary.clone()),
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| invalid(e.to_string()))?;
    let digest = hash(&bytes);
    write_new(&child.join(CONTINUATION_FILE), &manifest)?;
    // Ownership is published before spend state: interruption cannot open a fork.
    write_new(
        &active_path,
        &json!({"schemaVersion":1,"kind":"legion-audit-continuation-owner","child":child,"manifestDigest":digest}),
    )?;
    if let Some((record, applied, _)) = &generation {
        write_new(&child.join(PLAN_CHAIN_FILE), record)?;
        crate::amendment::record_in_journal(
            &child,
            &record.genesis_plan_digest,
            applied,
            applied.amendment.body.issued_at_unix,
        )?;
    }
    write_seed(&child, &manifest, &digest)?;
    validate_lineage(&child)?.ok_or_else(|| invalid("continuation ancestry missing"))
}

type Generation = (
    crate::amendment::AmendmentChainRecord,
    crate::amendment::AppliedAmendment,
    Value,
);

/// Build the signed ExtendBudget generation for a continuation. Only plans
/// that carry a finite-budget engagement have a budget to extend; every other
/// plan returns `None` and keeps the ledger-only continuation unchanged. The
/// target is `extended_max_tokens`, else the engagement authority ceiling; an
/// engagement without headroom refuses (the amendment contract enforces it).
fn plan_generation(
    child: &Path,
    operator_instruction: &str,
    extended_max_tokens: Option<u64>,
) -> Result<Option<Generation>, AuditError> {
    let plan_json = json_file(&child.join("plan.json"))?;
    let Some(native) = plan_json
        .get("nativePlan")
        .filter(|value| value.is_object())
    else {
        return Ok(None);
    };
    let Some(body) = native.get("plan").filter(|value| value.is_object()) else {
        return Ok(None);
    };
    let plan: crate::plan::AuditPlan = serde_json::from_value(body.clone())
        .map_err(|e| invalid(format!("continuation native plan malformed: {e}")))?;
    if plan.schema_version < crate::plan::PLAN_SCHEMA_V2 {
        return Ok(None);
    }
    let Some(engagement) = plan.engagement()? else {
        return Ok(None);
    };
    let Some(current) = engagement.stop_conditions.max_tokens else {
        return Ok(None);
    };
    let ceiling = engagement
        .authority
        .budget_ceiling_tokens
        .ok_or_else(|| invalid("continuation: engagement declares no budget ceiling"))?;
    let target = extended_max_tokens.unwrap_or(ceiling);
    if target <= current {
        return Err(invalid(
            "continuation: engagement authority has no budget headroom to extend",
        ));
    }
    let key = crate::integrity::plan_signing_key_for_run(child)?;
    let base = crate::amendment::frozen_plan_from_run_json(&plan_json, &key)?;
    if base.plan().generation()? != 1 {
        return Err(invalid(
            "continuation of an already amended plan generation is unsupported",
        ));
    }
    let issued = crate::amendment::now_unix();
    let mut amendment_body = crate::amendment::AmendmentBody::new(
        &base,
        format!("budget continuation: {}", operator_instruction.trim()),
        issued,
        vec![crate::amendment::AmendmentOperation::ExtendBudget { max_tokens: target }],
    )?;
    amendment_body.proposed_by = Some("continuation".into());
    let signed = crate::amendment::SignedAmendment::sign(amendment_body, &key)?;
    let (next, applied) = crate::amendment::apply(&base, &signed, &key)?;
    let record = crate::amendment::AmendmentChainRecord::new(&base, vec![applied.clone()], &next)?;
    let summary = json!({
        "genesisPlanDigest": base.digest(),
        "amendmentDigest": signed.digest,
        "resultGeneration": applied.result_generation,
        "resultPlanDigest": next.digest(),
        "extendedMaxTokens": target,
    });
    Ok(Some((record, applied, summary)))
}

/// Replay the recorded generation chain of a continuation child.
fn verify_plan_generation(run: &Path, manifest: &Manifest) -> Result<Option<Value>, AuditError> {
    let chain_path = run.join(PLAN_CHAIN_FILE);
    let Some(summary) = &manifest.plan_generation else {
        if chain_path.exists() {
            return Err(invalid(
                "continuation plan generation chain is not bound by the manifest",
            ));
        }
        return Ok(None);
    };
    let record: crate::amendment::AmendmentChainRecord =
        serde_json::from_slice(&read(&chain_path)?)
            .map_err(|e| invalid(format!("continuation plan generation chain invalid: {e}")))?;
    let key = crate::integrity::plan_signing_key_for_run(run)?;
    let genesis =
        crate::amendment::frozen_plan_from_run_json(&json_file(&run.join("plan.json"))?, &key)?;
    let end = record.verify(&genesis, &key)?;
    let [link] = record.links.as_slice() else {
        return Err(invalid("continuation plan generation must be one link"));
    };
    let op_ok = matches!(
        link.amendment.body.operations.as_slice(),
        [crate::amendment::AmendmentOperation::ExtendBudget { .. }]
    );
    if !op_ok
        || summary["genesisPlanDigest"] != json!(genesis.digest())
        || summary["amendmentDigest"] != json!(link.amendment.digest)
        || summary["resultPlanDigest"] != json!(end.digest())
        || summary["resultGeneration"] != json!(end.plan().generation()?)
    {
        return Err(invalid(
            "continuation plan generation differs from its manifest binding",
        ));
    }
    Ok(Some(summary.clone()))
}
fn write_seed(child: &Path, manifest: &Manifest, digest: &str) -> Result<(), AuditError> {
    let mut state = manifest.inherited_state.clone();
    state["dispatchDigest"] = json!(hash(&read(&child.join(DISPATCH_FILE))?));
    state["terminalStatus"] = Value::Null;
    state["continuationDigest"] = json!(digest);
    state["historicalTerminalStatus"] = json!(STOP);
    write_new(&child.join(STATE_FILE), &state)
}

/// Read-only lineage validation. Budget transactions call this under root lock;
/// verifiers may also call it directly. Historical violation always remains a gap.
pub fn validate_lineage(run: &Path) -> Result<Option<Value>, AuditError> {
    let path = run.join(CONTINUATION_FILE);
    if !path.exists() {
        if run.join(STATE_FILE).exists()
            && json_file(&run.join(STATE_FILE))?["continuationDigest"].is_string()
        {
            return Err(invalid(
                "continuation ancestry missing; budget cannot reset",
            ));
        }
        if run.join(DISPATCH_FILE).exists()
            && json_file(&run.join(DISPATCH_FILE))?
                .get("continuationRecipe")
                .is_some()
        {
            return Err(invalid(
                "continuation recipe has no linked ancestry; fresh budget refused",
            ));
        }
        return Ok(None);
    }
    let bytes = read(&path)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| invalid(format!("invalid continuation manifest: {e}")))?;
    let digest = hash(&bytes);
    if manifest.schema_version != 1
        || manifest.kind != KIND
        || canonical(run)? != manifest.child
        || canonical(&manifest.parent)? != manifest.parent
        || manifest.operator_instruction.trim().is_empty()
        || manifest.parent.join(CONTINUATION_FILE).exists()
    {
        return Err(invalid("continuation ancestry identity/schema invalid"));
    }
    let active = json_file(&manifest.parent.join(ACTIVE_FILE))?;
    if active["schemaVersion"] != 1
        || active["kind"] != "legion-audit-continuation-owner"
        || active["child"] != json!(manifest.child)
        || active["manifestDigest"] != digest
    {
        return Err(invalid(
            "continuation ownership binding mismatch or sibling fork",
        ));
    }
    if collect_files(&manifest.parent, false)? != manifest.parent_files {
        return Err(invalid("continuation immutable parent changed"));
    }
    require_files(run, &manifest.child_recipe)?;
    if collect_files(run, true)? != manifest.child_recipe {
        return Err(invalid("continuation recipe changed after freeze"));
    }
    let state = json_file(&run.join(STATE_FILE))?;
    let parent_state = json_file(&manifest.parent.join(STATE_FILE))?;
    if parent_state != manifest.inherited_state
        || parent_state["terminalStatus"] != STOP
        || state["historicalTerminalStatus"] != STOP
        || state["continuationDigest"] != digest
        || state["dispatchDigest"] != hash(&read(&run.join(DISPATCH_FILE))?)
    {
        return Err(invalid(
            "continuation inherited stop/accounting binding changed",
        ));
    }
    for field in ["issuances", "adjudicationRound"] {
        if checked_u64(&state, field)? < checked_u64(&parent_state, field)? {
            return Err(invalid(format!("continuation reset inherited {field}")));
        }
    }
    for (tier, amount) in parent_state["spent"]
        .as_object()
        .ok_or_else(|| invalid("inherited spend missing"))?
    {
        if state["spent"][tier].as_u64().unwrap_or(0)
            < amount
                .as_u64()
                .ok_or_else(|| invalid("inherited spend malformed"))?
        {
            return Err(invalid("continuation reset cumulative charged tokens"));
        }
    }
    for (id, reservation) in parent_state["reservations"]
        .as_object()
        .ok_or_else(|| invalid("inherited reservations missing"))?
    {
        if state["reservations"][id] != *reservation {
            return Err(invalid(
                "continuation changed inherited reservation/usage/cost",
            ));
        }
    }
    for (id, lease) in parent_state["leases"]
        .as_object()
        .ok_or_else(|| invalid("inherited attempts missing"))?
    {
        if state["leases"][id] != *lease {
            return Err(invalid("continuation changed inherited attempts"));
        }
    }
    let generation = verify_plan_generation(run, &manifest)?;
    let mut lineage = json!({"schemaVersion":1,"kind":KIND,"parent":manifest.parent,"child":manifest.child,"manifestDigest":digest,"historicalTerminalStatus":STOP,"historicalGap":format!("reasoning-budget-history:{STOP}"),"operatorInstruction":manifest.operator_instruction});
    if let Some(generation) = generation {
        lineage["planGeneration"] = generation;
    }
    Ok(Some(lineage))
}

/// Express the budget continuation through the general signed-amendment
/// contract. `lineage` is the value returned by `prepare`/`validate_lineage`
/// (it must be a continuation lineage). The returned body raises the frozen
/// engagement token budget to `extended_max_tokens`; applying it (sign, then
/// `amendment::apply`) enforces the engagement authority ceiling and produces
/// a new signed plan generation. The filesystem ledger API above is unchanged.
pub fn budget_amendment_body(
    base: &crate::plan::FrozenPlan,
    lineage: &Value,
    extended_max_tokens: u64,
    issued_at_unix: u64,
) -> Result<crate::amendment::AmendmentBody, AuditError> {
    if lineage["kind"] != KIND || lineage["historicalTerminalStatus"] != STOP {
        return Err(invalid("budget amendment requires a continuation lineage"));
    }
    let manifest_digest = lineage["manifestDigest"]
        .as_str()
        .filter(|digest| !digest.is_empty())
        .ok_or_else(|| invalid("continuation lineage lacks a manifest digest"))?;
    let mut body = crate::amendment::AmendmentBody::new(
        base,
        format!("budget continuation {manifest_digest}: explicit operator resume"),
        issued_at_unix,
        vec![crate::amendment::AmendmentOperation::ExtendBudget {
            max_tokens: extended_max_tokens,
        }],
    )?;
    body.proposed_by = Some(format!("continuation:{manifest_digest}"));
    Ok(body)
}
