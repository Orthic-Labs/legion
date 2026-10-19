//! Read-only observations over genuine production security pipeline runs.
//! Literal controls do not adjudicate semantic correctness or issue qualification.
use legion_audit::{
    native_providers::reasoning::{
        followup::{self, FollowupState},
        ingest::{self, Recomputed},
        security_adjudication::{self, ScannerCandidate, SecurityVerdict, ADJUDICATOR_PROVIDER_ID},
    },
    plan::AuditPlan,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Corpus {
    schema: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    id: String,
    control: Control,
    run: String,
    source_files: BTreeMap<String, String>,
    candidate: CandidateLabel,
    variant: Option<VariantLabel>,
    negative_challenges: Vec<Challenge>,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum Control {
    AdjudicationSurvivor,
    AdjudicationDismissal,
    VariantPositive,
    VariantAbsence,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateLabel {
    provider: String,
    rule: String,
    path: String,
    line: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VariantLabel {
    location: String,
    present: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Challenge {
    path: String,
    line: u64,
    rationale: String,
}

fn relative(value: &str) -> Result<&Path, String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains(['\\', ':'])
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("non-portable relative path: {value}"));
    }
    Ok(path)
}
fn within(root: &Path, value: &str) -> Result<PathBuf, String> {
    let mut path = root.to_owned();
    for part in relative(value)?.components() {
        path.push(part);
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("symlink evidence: {}", path.display()));
        }
    }
    Ok(path)
}
fn bytes(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        return Err("evidence must be a regular file <=64MiB".into());
    }
    let mut out = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() as u64 != meta.len() {
        return Err("evidence changed while reading".into());
    }
    Ok(out)
}
fn digest(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}
fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&bytes(path)?).map_err(|e| format!("{}: {e}", path.display()))
}
fn binding(path: &Path) -> Result<Value, String> {
    let data = bytes(path)?;
    Ok(json!({"path":path,"digest":digest(&data),"bytes":data.len()}))
}
fn complete_provider<'a>(
    run: &'a Recomputed,
    id: &str,
) -> Result<&'a legion_contracts::ProviderResult, String> {
    if !run.ingested.iter().any(|value| value == id) || run.pending.iter().any(|value| value == id)
    {
        return Err(format!(
            "authenticated complete ingestion unavailable: {id}"
        ));
    }
    let result = &run
        .execution
        .results
        .iter()
        .find(|entry| entry.provider == id)
        .ok_or_else(|| format!("provider not executed: {id}"))?
        .result;
    result.validate().map_err(|e| e.to_string())?;
    if !result.complete || !result.coverage_gaps.is_empty() {
        return Err(format!("incomplete provider: {id}"));
    }
    Ok(result)
}
fn runtime_calls(run: &Path) -> Result<Vec<Value>, String> {
    let dir = within(run, "runtime-calls")?;
    let mut paths = fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map(|entry| entry.path()).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let envelope = read_json(&path)?;
        ingest::verify_runtime_call(run, &envelope).map_err(|e| e.to_string())?;
        out.push(binding(&path)?);
    }
    if out.is_empty() {
        return Err("authenticated native runtime call evidence absent".into());
    }
    Ok(out)
}
// Retained production diagnostics contain original SDK stream descriptors +
// exact bytes after private scratch cleanup. Never treat reduced projections as
// a full SDK receipt, or reopen their expired original paths.
fn native_scanner(
    run: &Path,
    provider: &str,
    inventory: &str,
    projection: &Value,
) -> Result<Value, String> {
    let directory = within(run, "native-diagnostics")?;
    let mut matches = Vec::new();
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let raw = bytes(&path)?;
        let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if value["provider"] != provider || value["receipt"]["receiptId"] != projection["receiptId"]
        {
            continue;
        }
        let expected_name = format!(
            "{}-{}.json",
            provider,
            digest(&raw).trim_start_matches("sha256:")
        );
        if path.file_name().and_then(|v| v.to_str()) != Some(&expected_name)
            || value["schema"] != "legion-native-scanner-diagnostic/1"
            || value["inventoryDigest"] != inventory
        {
            return Err("native diagnostic identity/content binding invalid".into());
        }
        let receipt = &value["receipt"];
        if receipt["complete"] != true
            || receipt["state"] != "completed"
            || receipt["processTree"]["started"] != true
            || receipt["processTree"]["reaped"] != true
            || receipt["policy"]["allowed"] != true
            || receipt["providerId"] != provider
            || receipt["planId"] != inventory
            || receipt["exitCode"] != projection["exitCode"]
            || receipt["state"] != projection["state"]
        {
            return Err("actual native scanner receipt incomplete or detached".into());
        }
        for stream in ["stdout", "stderr"] {
            let record = &receipt[stream];
            let retained = &value[stream];
            let raw: Vec<u8> =
                serde_json::from_value(retained["rawBytes"].clone()).map_err(|e| e.to_string())?;
            if record["immutable"] != true
                || retained["immutable"] != true
                || record["digest"] != digest(&raw)
                || record["bytes"].as_u64() != Some(raw.len() as u64)
                || retained["digest"] != record["digest"]
                || retained["bytes"] != record["bytes"]
                || retained["originalPath"] != record["path"]
            {
                return Err("original SDK stream descriptor/raw-byte binding invalid".into());
            }
            if stream == "stdout"
                && (projection["stdoutDigest"] != record["digest"]
                    || projection["stdoutBytes"] != record["bytes"])
            {
                return Err("scanner projection/raw output binding differs".into());
            }
        }
        // Raw scanner streams stay in their existing private diagnostic artifact.
        // Observation output retains original full receipt + verifiable file binding.
        matches.push(json!({"artifact":binding(&path)?,"receipt":receipt}));
    }
    if matches.len() != 1 {
        return Err(format!(
            "expected one genuine native diagnostic for {provider}, found {}",
            matches.len()
        ));
    }
    Ok(matches.remove(0))
}
fn observe(case: &Case, runs: &Path) -> Result<Value, String> {
    let dir = within(runs, &case.run)?;
    let plan = read_json(&within(&dir, "plan.json")?)?;
    // Historical artifact-less plans are deliberately readable by production,
    // but cannot supply actual scanner execution controls here.
    if plan["effectArtifactsRoot"] != "artifacts" || plan.get("nativePlan").is_none() {
        return Err("native signed plan + private effect-artifact retention required".into());
    }
    let rebuilt = ingest::recompute_run(&dir).map_err(|e| e.to_string())?;
    let native: AuditPlan =
        serde_json::from_value(plan["nativePlan"]["plan"].clone()).map_err(|e| e.to_string())?;
    let root = fs::canonicalize(&native.repository_id).map_err(|e| e.to_string())?;
    if case.source_files.is_empty() {
        return Err("literal source bindings absent".into());
    }
    let mut source = Vec::new();
    for (path, expected) in &case.source_files {
        let file = within(&root, path)?;
        let actual = binding(&file)?;
        if actual["digest"].as_str() != Some(expected) {
            return Err(format!("literal source binding differs: {path}"));
        }
        source.push(actual);
    }
    if case.candidate.line == 0 || !case.source_files.contains_key(&case.candidate.path) {
        return Err("candidate label must bind a nonzero source line".into());
    }
    let mut candidates: Vec<ScannerCandidate> = Vec::new();
    let mut scanner_receipts = Vec::new();
    for generator in native
        .providers
        .iter()
        .filter(|provider| provider.role == "candidate-generator")
    {
        let entry = rebuilt
            .execution
            .results
            .iter()
            .find(|entry| entry.provider == generator.id)
            .ok_or_else(|| format!("generator execution absent: {}", generator.id))?;
        let actual =
            security_adjudication::scanner_candidates(&root, &entry.provider, &entry.result);
        if !actual.is_empty() {
            let receipt = entry
                .result
                .details
                .get("executionReceipt")
                .ok_or("actual scanner receipt absent")?;
            if entry.skipped
                || !entry.result.complete
                || !entry.result.coverage_gaps.is_empty()
                || entry
                    .result
                    .details
                    .get("producer")
                    .and_then(|v| v.get("mode"))
                    .and_then(Value::as_str)
                    != Some("tool")
            {
                return Err(format!(
                    "actual complete native scanner execution unavailable: {}",
                    entry.provider
                ));
            }
            scanner_receipts.push(native_scanner(
                &dir,
                &entry.provider,
                &rebuilt.execution.inventory_digest,
                receipt,
            )?);
        }
        candidates.extend(actual);
    }
    let ids = candidates
        .iter()
        .map(|v| v.finding_id.as_str())
        .collect::<BTreeSet<_>>();
    if candidates.is_empty() || ids.len() != candidates.len() {
        return Err("scanner candidate inventory empty or duplicated".into());
    }
    let selected = candidates
        .iter()
        .filter(|item| {
            item.provider == case.candidate.provider
                && item.rule == case.candidate.rule
                && item.path.as_deref() == Some(case.candidate.path.as_str())
                && item.line == Some(case.candidate.line)
        })
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err("literal label must match exactly one actual scanner candidate".into());
    }
    let adjudication = complete_provider(&rebuilt, ADJUDICATOR_PROVIDER_ID)?;
    if adjudication
        .details
        .get("adjudicationLedger")
        .and_then(|v| v.pointer("/ledger/complete"))
        != Some(&Value::Bool(true))
        || adjudication
            .details
            .get("adjudicationDeliveryEvidence")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err("authenticated staged independent adjudication unavailable".into());
    }
    let verdicts: Vec<SecurityVerdict> = serde_json::from_value(
        adjudication
            .details
            .get("securityVerdicts")
            .cloned()
            .ok_or("verdicts absent")?,
    )
    .map_err(|e| e.to_string())?;
    let verdict_ids = verdicts
        .iter()
        .map(|v| v.candidate_id.as_str())
        .collect::<BTreeSet<_>>();
    if verdict_ids != ids || verdict_ids.len() != verdicts.len() {
        return Err("complete scanner/verdict identity reconciliation failed".into());
    }
    let chosen = verdicts
        .iter()
        .find(|v| v.candidate_id == selected[0].finding_id)
        .ok_or("selected verdict absent")?;
    let survival_expected = case.control != Control::AdjudicationDismissal;
    let mut matched = if survival_expected {
        chosen.verdict.is_surviving()
    } else {
        chosen.verdict.is_dismissal()
    };
    let adjudicated_id = format!("adjudicated:{}", chosen.candidate_id);
    let survives = rebuilt.confirmed_security.iter().any(|finding| {
        finding.candidate_id == chosen.candidate_id
            && finding.verdict_digest == chosen.verdict_digest
    });
    if survival_expected {
        matched &= survives
            && rebuilt
                .report
                .findings
                .iter()
                .any(|finding| finding.id.as_str() == adjudicated_id);
    } else {
        matched &= !survives
            && !rebuilt
                .report
                .findings
                .iter()
                .any(|finding| finding.id.as_str() == adjudicated_id);
    }
    let calls = runtime_calls(&dir)?;
    let mut followup_observation = Value::Null;
    if matches!(
        case.control,
        Control::VariantPositive | Control::VariantAbsence
    ) {
        let label = case
            .variant
            .as_ref()
            .ok_or("variant literal label absent")?;
        if label.present != (case.control == Control::VariantPositive) {
            return Err("variant role/expectation mismatch".into());
        }
        let (path, line) = label
            .location
            .rsplit_once(':')
            .ok_or("variant label needs exact file:line")?;
        if !case.source_files.contains_key(path)
            || line.parse::<u64>().ok().is_none_or(|line| line == 0)
        {
            return Err("variant label is not source-bound".into());
        }
        let state =
            followup::evaluate(&dir, &plan, &rebuilt.execution, &rebuilt.confirmed_security);
        let FollowupState::Complete(done) = &state else {
            return Err(format!("genuine followup incomplete: {}", state.claim()));
        };
        let child = within(&dir, followup::FOLLOWUP_DIR)?;
        let child_rebuilt = ingest::recompute_run(&child).map_err(|e| e.to_string())?;
        complete_provider(&child_rebuilt, followup::VARIANT_PROVIDER_ID)?;
        let observed = done.findings.iter().any(|finding| {
            finding.provider.as_deref() == Some(followup::VARIANT_PROVIDER_ID)
                && finding
                    .locations
                    .iter()
                    .any(|value| value == &label.location)
        });
        matched &=
            observed == label.present && done.analysis_paths.iter().any(|value| value == path);
        followup_observation = json!({"chain":state.claim(),"runtimeCalls":runtime_calls(&child)?,
            "plan":binding(&child.join("plan.json"))?,"execution":binding(&child.join("execution.json"))?,
            "findings":done.findings,"literalLocation":label.location,"expectedPresent":label.present,"observedPresent":observed});
    } else if case.variant.is_some() {
        return Err("adjudication control carries unexpected variant label".into());
    }
    let mut challenges = Vec::new();
    for challenge in &case.negative_challenges {
        if challenge.line == 0
            || challenge.rationale.trim().is_empty()
            || !case.source_files.contains_key(&challenge.path)
        {
            return Err("negative-scope challenge must bind source line + rationale".into());
        }
        challenges.push(
            json!({"path":challenge.path,"line":challenge.line,"rationale":challenge.rationale,
            "semanticAdjudicationStatus":"unadjudicated","literalObservationMatches":matched}),
        );
    }
    if matches!(
        case.control,
        Control::AdjudicationDismissal | Control::VariantAbsence
    ) && challenges.is_empty()
    {
        return Err("negative control requires source-bound scope challenge ledger".into());
    }
    Ok(
        json!({"id":case.id,"status":if matched {"matches-literal-expectation"} else {"mismatch"},
        "semanticAdjudicationStatus":"unadjudicated","run":dir,"planDigest":rebuilt.execution.plan_digest,
        "inventoryDigest":rebuilt.execution.inventory_digest,"sourceFiles":source,"scannerCandidates":candidates,
        "scannerReceipts":scanner_receipts,"securityVerdicts":verdicts,"confirmedSecurity":rebuilt.confirmed_security,
        "adjudicationReceipt":adjudication.details.get("executionReceipt"),"adjudicationLedger":adjudication.details.get("adjudicationLedger"),
        "runtimeCalls":calls,"negativeScopeChallenges":challenges,"followup":followup_observation,
        "plan":binding(&dir.join("plan.json"))?,"execution":binding(&dir.join("execution.json"))?,"report":binding(&dir.join("report.json"))?,
        "remainingRunGaps":rebuilt.report.gaps}),
    )
}

/// Root wires this read-only entry into legion-dev. No launch, ingestion,
/// key creation, budget reset, report rewrite, or qualification registration.
pub fn run(corpus_path: &Path, runs_root: &Path) -> Result<Value, String> {
    let raw = bytes(corpus_path)?;
    let corpus: Corpus = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if corpus.schema != "legion-audit-security-controls/1" || corpus.cases.len() != 4 {
        return Err("expected security controls schema/1 with exactly four roles".into());
    }
    let mut roles = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for case in &corpus.cases {
        if case.id.trim().is_empty() || !ids.insert(&case.id) || !roles.insert(case.control) {
            return Err("duplicate/empty control identity".into());
        }
    }
    let root = fs::canonicalize(runs_root).map_err(|e| e.to_string())?;
    let controls = corpus.cases.iter().map(|case| observe(case, &root).unwrap_or_else(|error|
        json!({"id":case.id,"status":"unavailable","semanticAdjudicationStatus":"unadjudicated","error":error}))).collect::<Vec<_>>();
    let observations_match = controls
        .iter()
        .all(|value| value["status"] == "matches-literal-expectation");
    Ok(
        json!({"schema":"legion-audit-security-controls-observations/1","corpus":corpus_path,"corpusDigest":digest(&raw),
        "status":if observations_match {"observed-controls-unadjudicated"} else {"incomplete"},
        "semanticAdjudicationStatus":"unadjudicated","controls":controls}),
    )
}
