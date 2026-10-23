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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        native_providers::reasoning::ingest,
        next::{self, BudgetCall, NextOptions, UsageReceipt},
    };

    const RESUME: &str = "SSD is back, resume where you left off. Check CI, install verified build & finish Ember audit within same budget.";
    struct Fixture {
        base: PathBuf,
        parent: PathBuf,
        child: PathBuf,
    }
    fn source_snapshot(base: &Path) -> crate::snapshot::FrozenSnapshot {
        let source = base.join("source");
        fs::create_dir_all(&source).unwrap();
        let source = fs::canonicalize(source).unwrap();
        let git = |args: &[&str]| {
            let mut command = rightkit_child_process::OwnedCommand::new("git");
            command
                .command_mut()
                .current_dir(&source)
                .args(args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let mut child = command.spawn().unwrap();
            assert!(child
                .wait_timeout(std::time::Duration::from_secs(10))
                .unwrap()
                .unwrap()
                .success());
        };
        git(&["init", "-q"]);
        git(&["config", "user.name", "Audit Test"]);
        git(&["config", "user.email", "audit@example.invalid"]);
        fs::write(source.join("file.rs"), b"base\n").unwrap();
        git(&["add", "."]);
        git(&["-c", "commit.gpgsign=false", "commit", "-qm", "base"]);
        let scope =
            crate::scope::ResolvedScope::resolve(&source, crate::scope::ScopeSpec::Local, None)
                .unwrap();
        crate::snapshot::FrozenSnapshot::capture(scope).unwrap()
    }
    fn put(path: &Path, value: &Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
    fn call(id: &str) -> BudgetCall {
        BudgetCall {
            reservation_id: None,
            call_id: id.into(),
            tier: "judgment".into(),
            rendered_request_bytes: 100,
            model_input_bytes: 20,
            output_token_limit: 2500,
            retry: false,
        }
    }
    fn settle(run: &Path, authorization: &Value, input: u64, failed: bool) -> UsageReceipt {
        settle_with_output(run, authorization, input, 289, failed)
    }
    fn settle_with_output(
        run: &Path,
        authorization: &Value,
        input: u64,
        output: u64,
        failed: bool,
    ) -> UsageReceipt {
        let usage = UsageReceipt {
            reservation_id: authorization["reservationId"].as_str().unwrap().into(),
            receipt_id: format!("usage:{}", authorization["callId"].as_str().unwrap()),
            input_tokens: Some(input),
            output_tokens: Some(output),
            cached_input_tokens: Some(0),
            retry_tokens: Some(0),
            thinking_tokens: None,
            failed,
        };
        next::reconcile_native_usage(run, &usage, Some("0.046638")).unwrap();
        usage
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_usage(10938, 289)
        }
        fn with_usage(input: u64, output: u64) -> Self {
            let mut nonce = [0u8; 8];
            getrandom::fill(&mut nonce).unwrap();
            let base =
                std::env::temp_dir().join(format!("legion-continuation-{}", hex::encode(nonce)));
            let snapshot = source_snapshot(&base);
            let parent = base.join("parent");
            let child = base.join("child");
            fs::create_dir_all(parent.join("lens-packets")).unwrap();
            fs::create_dir_all(child.join("lens-packets")).unwrap();
            let epoch = ingest::create_epoch(&parent).unwrap();
            put(
                &parent.join("plan.json"),
                &json!({"epoch":{"digest":epoch},"reviewContext":{"snapshotManifest":snapshot.manifest_path,"snapshotKey":snapshot.manifest.key}}),
            );
            for file in ["facts.json", "execution.json", "inventory.json"] {
                put(&parent.join(file), &json!({"frozenEvidence":file}));
            }
            let budget = json!({"schemaVersion":2,"totalTokens":50000,"perCallTokens":10000,"outputTokens":2500,"maxSeats":5});
            put(
                &parent.join(DISPATCH_FILE),
                &json!({"reasoningBudget":budget,"limits":{"waveWidth":1},"seats":[{"seat":1,"seatId":"original-seat","tier":"judgment","gatherPolicy":"deterministic","packets":["reasoning.a.json"]}]}),
            );
            put(
                &parent.join("lens-packets/reasoning.a.json"),
                &json!({"frozenSource":"original"}),
            );
            let wave = next::next(
                &parent,
                &NextOptions {
                    now_ms: 1,
                    lease_ms: 1000,
                },
            )
            .unwrap();
            let mut request = call("original-call");
            request.reservation_id =
                Some(wave["seats"][0]["reservationId"].as_str().unwrap().into());
            let authorized = next::reserve_call(&parent, &request).unwrap();
            assert_eq!(authorized["authorized"], true);
            let usage = settle_with_output(&parent, &authorized, input, output, true);
            let request_digest = format!("sha256:{}", "2".repeat(64));
            let receipt = ingest::mint_runtime_call(&parent,&json!({"schemaVersion":1,"kind":"legion-runtime-call","callId":"original-call","seatId":"original-seat",
                "requestDigest":request_digest,"snapshotKey":snapshot.manifest.key,"requestBytes":100,
                "requestAccounting":{"basis":"serialized-host-envelope","nativeFramingIncluded":false,"providerInputTokenCountBeforeSend":null},
                "authorization":authorized,"observation":{"physicalRequestDigest":request_digest,"physicalRequestBytes":100,"usage":usage,"reportedApiEquivalentCostUsd":"0.046638","invoiceChargeUsd":null},"modelAction":null,
                "budget":{"status":"reconciled","budget":next::persisted_budget_report(&parent).unwrap().unwrap()["budget"]}})).unwrap();
            put(&parent.join("runtime-calls/original.json"), &receipt);
            for file in FOUNDATION {
                fs::copy(parent.join(file), child.join(file)).unwrap();
            }
            // Native key custody remains opaque to the fixture & its assertions.
            fs::copy(parent.join("epoch.key"), child.join("epoch.key")).unwrap();
            put(
                &child.join(DISPATCH_FILE),
                &json!({"reasoningBudget":budget,"limits":{"waveWidth":1},"continuationRecipe":{"schemaVersion":1,"kind":"frozen-source-rematerialization","modelsStarted":0},
                "seats":[{"seat":1,"seatId":"continuation-seat-001","tier":"judgment","gatherPolicy":"deterministic","packets":["reasoning.a.json"]},
                {"seat":2,"seatId":"continuation-seat-002","tier":"judgment","gatherPolicy":"deterministic","packets":["reasoning.b.json"]}]}),
            );
            for packet in ["reasoning.a.json", "reasoning.b.json"] {
                put(
                    &child.join("lens-packets").join(packet),
                    &json!({"frozenSource":"unfinished original source"}),
                );
            }
            Self {
                base,
                parent,
                child,
            }
        }
        fn prepare(&self) -> Value {
            prepare(&self.parent, &self.child, RESUME).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Git objects may be read-only on Windows. Clear that attribute
            // only inside this fixture; immutable snapshots live in Audit cache.
            #[cfg(windows)]
            for entry in walkdir::WalkDir::new(&self.base)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                if entry.file_type().is_file() {
                    if let Ok(metadata) = entry.metadata() {
                        let mut permissions = metadata.permissions();
                        if permissions.readonly() {
                            permissions.set_readonly(false);
                            let _ = fs::set_permissions(entry.path(), permissions);
                        }
                    }
                }
            }
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn engagement_plan(key: &[u8]) -> crate::plan::FrozenPlan {
        use crate::plan::{
            AuditPlan, AuditProvider, AuthorityMode, Engagement, EngagementAuthority,
            EngagementScope, ProviderKind, StopConditions, PLAN_SCHEMA_V2,
        };
        let mut configuration: BTreeMap<String, Value> = [
            "schemaVersion",
            "family",
            "selector",
            "denominatorKind",
            "hostCapabilities",
            "execution",
            "reasoning",
            "benchmark",
            "controlIds",
            "scopes",
            "selectable",
            "runnerClass",
            "denominatorDigest",
            "denominatorCount",
        ]
        .into_iter()
        .map(|field| (field.to_owned(), Value::Null))
        .collect();
        configuration.insert("runner".into(), json!({"kind": "built-in"}));
        configuration.insert("consumes".into(), json!([]));
        configuration.insert("produces".into(), json!([]));
        let provider = AuditProvider {
            id: "p.a".into(),
            version: "1".into(),
            role: "deterministic".into(),
            phase: "scan".into(),
            lens_ids: Vec::new(),
            dependencies: Vec::new(),
            kind: ProviderKind::BuiltIn,
            configuration,
            bounds: BTreeMap::new(),
            clean_claim: "claim".into(),
            benchmark_status: "unqualified".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: true,
        };
        let plan = AuditPlan {
            schema_version: PLAN_SCHEMA_V2,
            repository_id: "/frozen/source".into(),
            inventory_generation: "gen".into(),
            inventory_digest: "inventory".into(),
            providers: vec![provider],
            bounds: crate::execution_policy::binding()
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            excluded_conditional_providers: Vec::new(),
        };
        let engagement = Engagement {
            format: "audit-engagement/v1".into(),
            engagement_id: "eng-1".into(),
            authority: EngagementAuthority {
                mode: AuthorityMode::Explicit,
                principal: "operator".into(),
                approval_ref: Some("approval-1".into()),
                expires_at_unix: Some(4_000_000_000),
                budget_ceiling_tokens: Some(1000),
            },
            scope: EngagementScope {
                include: vec!["**".into()],
                exclude: vec![".git/**".into()],
                revision: None,
            },
            strategy: vec!["security".into()],
            stop_conditions: StopConditions {
                max_tokens: Some(500),
                max_seconds: Some(600),
                stop_on_severity: Some("critical".into()),
                breaker_failures: Some(3),
            },
        };
        plan.with_engagement(&engagement)
            .unwrap()
            .with_objective_graph()
            .unwrap()
            .freeze(Some(key))
            .unwrap()
    }

    #[test]
    fn engagement_continuation_records_a_verified_budget_generation() {
        let f = Fixture::new();
        let key = ingest::load_epoch(&f.parent).unwrap().0;
        let frozen = engagement_plan(&key);
        let mut plan_json = json_file(&f.parent.join("plan.json")).unwrap();
        plan_json["nativePlan"] = json!({"schemaVersion":1,"digest":frozen.digest(),
            "signature":frozen.signature(),"plan":serde_json::to_value(frozen.plan()).unwrap()});
        put(&f.parent.join("plan.json"), &plan_json);
        fs::copy(f.parent.join("plan.json"), f.child.join("plan.json")).unwrap();
        let lineage = f.prepare();
        assert_eq!(lineage["planGeneration"]["resultGeneration"], 2);
        assert_eq!(lineage["planGeneration"]["extendedMaxTokens"], 1000);
        assert_eq!(f.prepare(), lineage, "replay re-verifies the same chain");
        assert!(f.child.join(PLAN_CHAIN_FILE).is_file());
        assert_eq!(validate_lineage(&f.child).unwrap().unwrap(), lineage);
        // A forged chain link no longer verifies.
        let mut chain = json_file(&f.child.join(PLAN_CHAIN_FILE)).unwrap();
        chain["links"][0]["amendment"]["body"]["operations"][0]["maxTokens"] = json!(999);
        fs::write(
            f.child.join(PLAN_CHAIN_FILE),
            serde_json::to_vec(&chain).unwrap(),
        )
        .unwrap();
        assert!(validate_lineage(&f.child).is_err());
    }

    #[test]
    fn authenticated_continuation_preserves_parent_history_and_full_verifier_reserve() {
        let f = Fixture::new();
        let original = collect_files(&f.parent, false).unwrap();
        let allowance = planning_budget(&f.parent).unwrap();
        assert_eq!(allowance["remainingTokens"], 38773);
        assert_eq!(allowance["remainingCalls"], 3);
        let linked = f.prepare();
        assert_eq!(f.prepare(), linked, "same explicit child is idempotent");
        assert_eq!(
            collect_files(&f.parent, false).unwrap(),
            original,
            "every original parent byte remains immutable"
        );
        let state = json_file(&f.child.join(STATE_FILE)).unwrap();
        assert_eq!(state["leases"]["original-seat"]["attempts"], 1);
        assert_eq!(
            state["adjudicationRound"],
            json_file(&f.parent.join(STATE_FILE)).unwrap()["adjudicationRound"]
        );
        for id in ["author-one", "author-two"] {
            assert!(next::native_author_has_verifier_reserve(&f.child, None).unwrap());
            let authorization = next::reserve_call(&f.child, &call(id)).unwrap();
            assert_eq!(authorization["authorized"], true);
            settle(&f.child, &authorization, 100, false);
        }
        assert!(
            !next::native_author_has_verifier_reserve(&f.child, None).unwrap(),
            "third author cannot consume verifier allowance"
        );
        let verifier = next::reserve_call(&f.child, &call("fresh-verifier")).unwrap();
        assert_eq!(verifier["authorized"], true);
        settle(&f.child, &verifier, 100, false);
        assert_eq!(
            next::reserve_call(&f.child, &call("beyond-root-budget")).unwrap()["authorized"],
            false
        );
        let report = next::persisted_budget_report(&f.child).unwrap().unwrap();
        assert_eq!(report["budget"]["chargedByTier"]["judgment"], 41227);
        assert_eq!(report["budget"]["failedCalls"], 1);
        assert_eq!(report["budget"]["actualOverrunTokens"], 1227);
        assert_eq!(
            report["budget"]["cost"]["reportedApiEquivalentCostUsd"],
            "0.186552"
        );
        assert!(report["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap == "reasoning-budget-history:incomplete:budget-overrun"));
        assert_eq!(collect_files(&f.parent, false).unwrap(), original);
    }

    #[test]
    fn continuation_keeps_old_attempts_without_old_active_lease_blocking_new_recipe() {
        let f = Fixture::new();
        f.prepare();
        let next = next::next(
            &f.child,
            &NextOptions {
                now_ms: 2,
                lease_ms: 1000,
            },
        )
        .unwrap();
        assert_eq!(next["seats"][0]["seatId"], "continuation-seat-001");
        assert_eq!(next["progress"]["leaseIssuances"], 2);
        assert_eq!(
            json_file(&f.child.join(STATE_FILE)).unwrap()["leases"]["original-seat"]["attempts"],
            1
        );
    }

    #[test]
    fn unbound_staged_recipe_never_opens_fresh_ledger() {
        let f = Fixture::new();
        assert!(next::reserve_call(&f.child, &call("must-not-run")).is_err());
        assert!(next::next(
            &f.child,
            &NextOptions {
                now_ms: 2,
                lease_ms: 1000
            }
        )
        .is_err());
        assert!(validate_lineage(&f.child).is_err());
        assert!(next::persisted_budget_report(&f.child).is_err());
        assert!(!f.child.join(STATE_FILE).exists());
        assert!(collect_files(&f.parent, false)
            .unwrap()
            .contains_key(STATE_FILE));
    }

    #[test]
    fn sibling_resume_replay_or_nested_continuation_cannot_fork_budget() {
        let f = Fixture::new();
        f.prepare();
        let sibling = f.base.join("sibling");
        fs::create_dir_all(&sibling).unwrap();
        assert!(prepare(&f.parent, &sibling, RESUME).is_err());
        assert!(prepare(&f.parent, &f.child, "different resume instruction").is_err());
        assert!(prepare(&f.child, &sibling, RESUME).is_err());
        assert!(
            next::reserve_call(&f.child, &call("original-call")).is_err(),
            "inherited physical call IDs remain consumed"
        );
    }

    #[test]
    fn missing_ancestry_or_spent_ledger_never_reseeds_child() {
        let f = Fixture::new();
        f.prepare();
        let admitted = next::reserve_call(&f.child, &call("child-spend")).unwrap();
        settle(&f.child, &admitted, 100, false);
        let ledger = read(&f.child.join(STATE_FILE)).unwrap();
        fs::remove_file(f.child.join(STATE_FILE)).unwrap();
        assert!(prepare(&f.parent, &f.child, RESUME).is_err());
        assert!(next::persisted_budget_report(&f.child).is_err());
        assert!(!f.child.join(STATE_FILE).exists());
        fs::write(f.child.join(STATE_FILE), ledger).unwrap();
        fs::remove_file(f.child.join(CONTINUATION_FILE)).unwrap();
        assert!(next::reserve_call(&f.child, &call("lost-ancestry")).is_err());
    }

    #[test]
    fn changed_parent_recipe_or_inherited_charge_fails_lineage() {
        let f = Fixture::new();
        f.prepare();
        let state_path = f.child.join(STATE_FILE);
        let original = read(&state_path).unwrap();
        let mut state = json_file(&state_path).unwrap();
        state["spent"]["judgment"] = json!(10000);
        put(&state_path, &state);
        assert!(next::reserve_call(&f.child, &call("reset-charge")).is_err());
        fs::write(&state_path, &original).unwrap();
        let packet = f.child.join("lens-packets/reasoning.a.json");
        let packet_bytes = read(&packet).unwrap();
        fs::write(&packet, b"changed recipe").unwrap();
        assert!(validate_lineage(&f.child).is_err());
        fs::write(packet, packet_bytes).unwrap();
        fs::write(
            f.parent.join("runtime-calls/original.json"),
            b"changed parent",
        )
        .unwrap();
        assert!(next::reserve_call(&f.child, &call("mutated-parent")).is_err());
    }

    #[test]
    fn unknown_cost_usage_or_unauthenticated_fake_stop_cannot_continue() {
        let f = Fixture::new();
        let path = f.parent.join(STATE_FILE);
        let original = read(&path).unwrap();
        let original_state = json_file(&path).unwrap();
        let id = original_state["reservations"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        for unknown_cost in [false, true] {
            let mut state = original_state.clone();
            if unknown_cost {
                state["reservations"][&id]["reportedApiCostUsd"] = Value::Null;
            } else {
                state["reservations"][&id]["usage"]["inputTokens"] = Value::Null;
            }
            put(&path, &state);
            assert!(prepare(&f.parent, &f.child, RESUME).is_err());
        }
        let mut fake = original_state.clone();
        fake["reservations"][&id]["usage"]["inputTokens"] = json!(100);
        put(&path, &fake);
        assert!(
            prepare(&f.parent, &f.child, RESUME).is_err(),
            "terminal label alone cannot authorize resume"
        );
        fs::write(&path, original).unwrap();
        let receipt_path = f.parent.join("runtime-calls/original.json");
        let mut receipt = json_file(&receipt_path).unwrap();
        receipt["observation"]["usage"]["inputTokens"] = json!(1);
        put(&receipt_path, &receipt);
        assert!(
            prepare(&f.parent, &f.child, RESUME).is_err(),
            "MAC-authenticated usage is required"
        );
        assert!(!f.child.join(STATE_FILE).exists());
    }

    #[test]
    fn continuation_cannot_raise_ceilings_or_omit_fresh_verification_reserve() {
        let f = Fixture::new();
        let path = f.child.join(DISPATCH_FILE);
        let original = json_file(&path).unwrap();
        let mut raised = original.clone();
        raised["reasoningBudget"]["totalTokens"] = json!(60000);
        put(&path, &raised);
        assert!(prepare(&f.parent, &f.child, RESUME).is_err());
        let mut crowded = original.clone();
        let mut extra = crowded["seats"][0].clone();
        extra["seatId"] = json!("continuation-seat-003");
        extra["seat"] = json!(3);
        crowded["seats"].as_array_mut().unwrap().push(extra);
        put(&path, &crowded);
        assert!(
            prepare(&f.parent, &f.child, RESUME).is_err(),
            "three authors plus verifier exceed 38773 remaining tokens"
        );
        assert!(!f.child.join(STATE_FILE).exists());
    }

    #[test]
    fn subsequent_overrun_stays_terminal_and_retains_original_violation() {
        let f = Fixture::new();
        f.prepare();
        let admitted = next::reserve_call(&f.child, &call("new-overrun")).unwrap();
        settle(&f.child, &admitted, 10001, false);
        let before = read(&f.child.join(STATE_FILE)).unwrap();
        assert_eq!(
            next::reserve_call(&f.child, &call("after-overrun")).unwrap()["status"],
            STOP
        );
        assert_eq!(read(&f.child.join(STATE_FILE)).unwrap(), before);
        let report = next::persisted_budget_report(&f.child).unwrap().unwrap();
        assert_eq!(report["budget"]["historicalTerminalStatus"], STOP);
        assert_eq!(report["budget"]["actualOverrunTokens"], 1517);
    }

    #[test]
    fn output_only_overrun_cannot_release_original_authenticated_full_allowance() {
        let f = Fixture::with_usage(100, 2501);
        let path = f.parent.join(STATE_FILE);
        let mut state = json_file(&path).unwrap();
        let id = state["reservations"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        // Internally consistent fabricated charge: actual total is below the
        // original allowance, while output alone violated its frozen cap.
        state["reservations"][&id]["reservedTokens"] = json!(2601);
        state["spent"]["judgment"] = json!(2601);
        put(&path, &state);
        assert!(
            prepare(&f.parent, &f.child, RESUME).is_err(),
            "sealed authorization retains all 10k charged tokens"
        );
        assert!(!f.child.join(STATE_FILE).exists());
    }
}
