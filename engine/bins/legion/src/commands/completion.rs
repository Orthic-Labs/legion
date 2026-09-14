//! Authenticated completion claim and Oracle evidence persistence.
use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_arcane::receipt_auth::{sign_record, verify_record};
use legion_arcane::{AuthorityInvocationProofIssuer, KeyRing, ReceiptStore, SessionBindingStore};
use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const HOST_FIELDS: [&str; 19] = [
    "schemaVersion",
    "kind",
    "eventId",
    "eventSequence",
    "previousDigest",
    "turnCorrelationDigest",
    "stopOrdinal",
    "adapter",
    "eventType",
    "sessionId",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "sourceRevision",
    "observedAuthority",
    "payloadDigest",
    "observedAt",
];
const EVIDENCE_FIELDS: [&str; 13] = [
    "schemaVersion",
    "kind",
    "evidenceId",
    "runId",
    "taskId",
    "contractId",
    "producerAuthority",
    "capability",
    "observation",
    "evidenceClass",
    "sourceRevision",
    "dependsOn",
    "observedAt",
];
fn arg(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|p| p[0] == n).map(|p| p[1].clone())
}
fn session(a: &[String]) -> Result<String, CommandError> {
    arg(a, "--session")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("CODEX_THREAD_ID").ok())
        .or_else(|| std::env::var("CLAUDE_CODE_SESSION_ID").ok())
        .or_else(|| std::env::var("CLAUDE_SESSION_ID").ok())
        .or_else(|| std::env::var("CODEX_SESSION_ID").ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            CommandError::usage("completion requires --session <id> for authenticated binding")
        })
}
fn root() -> Result<PathBuf, CommandError> {
    std::env::current_dir().map_err(super::io_error)
}
fn ring(a: &[String]) -> Result<KeyRing, CommandError> {
    let p = arg(a, "--key-dir")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("ARCANE_KEY_DIR").map(PathBuf::from));
    match p {
        Some(p) => KeyRing::load_dir(&p).map_err(|e| CommandError::incomplete(e.to_string())),
        None => KeyRing::load_canonical().map_err(|e| CommandError::incomplete(e.to_string())),
    }
}
fn hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}
fn seal(root: &Path, b: &Value) -> Result<Value, CommandError> {
    let p = legion_arcane::state_paths::state_file(
        &root.join(".audit/arcane/contract-seals"),
        "arcane.contract-seal.key.v1",
        &[
            b["contractId"].as_str().unwrap_or_default().into(),
            b["contractVersion"]
                .as_u64()
                .unwrap_or_default()
                .to_string(),
        ],
    )
    .map_err(|e| CommandError::integrity(e.to_string()))?;
    serde_json::from_slice(
        &fs::read(p).map_err(|_| CommandError::incomplete("ARC_CONTRACT_VERSION_MISMATCH"))?,
    )
    .map_err(|_| CommandError::incomplete("ARC_STORE_CORRUPT: unreadable contract seal"))
}
fn events(root: &Path, session: &str, k: &KeyRing) -> Result<Vec<Value>, CommandError> {
    let dir = root.join(".audit/arcane/host-events");
    let mut files = fs::read_dir(&dir)
        .map_err(|_| {
            CommandError::incomplete(
                "ARC_STORE_CORRUPT: host event ledger continuity is unavailable",
            )
        })?
        .flatten()
        .filter(|e| {
            e.file_name().to_string_lossy().ends_with(".json")
                && e.file_name().to_string_lossy().len() == 21
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|e| e.file_name());
    let mut out = Vec::new();
    let mut prev: Option<String> = None;
    for f in files {
        let v: Value = serde_json::from_slice(
            &fs::read(f.path()).map_err(|_| CommandError::incomplete("ARC_STORE_CORRUPT"))?,
        )
        .map_err(|_| CommandError::incomplete("ARC_STORE_CORRUPT"))?;
        let auth = v
            .get("authentication")
            .ok_or_else(|| CommandError::incomplete("ARC_STORE_CORRUPT"))?;
        let d = verify_record(&v, Some(auth), k, &HOST_FIELDS, &Map::new(), None)
            .map_err(|_| CommandError::incomplete("ARC_STORE_CORRUPT"))?;
        if !d.allowed || v["previousDigest"].as_str() != prev.as_deref() {
            return Err(CommandError::incomplete(
                "ARC_STORE_CORRUPT: host event ledger continuity is unavailable",
            ));
        }
        prev = Some(canonical_digest(&v).map_err(|e| CommandError::integrity(e.to_string()))?);
        if v["sessionId"].as_str() == Some(session) {
            out.push(v)
        }
    }
    if out.is_empty() {
        return Err(CommandError::incomplete(
            "ARC_AUTHORITY_NOT_ASSERTED: current authenticated authority event required",
        ));
    }
    Ok(out)
}
fn claim(root: &Path, a: &[String], file: &str, b: &Value, s: &str, k: KeyRing) -> CommandResult {
    let outcome: Value = serde_json::from_slice(
        &fs::read(file)
            .map_err(|e| CommandError::usage(format!("invalid completion artifact: {e}")))?,
    )
    .map_err(|e| CommandError::usage(format!("invalid completion artifact: {e}")))?;
    if !outcome.is_object() {
        return Err(CommandError::usage(
            "completion artifact must contain a JSON object",
        ));
    }
    if outcome.get("outcomeSummary").is_none() || outcome.get("artifactState").is_none() {
        return Err(CommandError::usage(
            "completion claim artifact requires outcomeSummary and artifactState",
        ));
    }
    let es = events(root, s, &k)?;
    let event = es
        .iter()
        .rev()
        .find(|e| {
            matches!(
                e["observedAuthority"].as_str(),
                Some("legion" | "alchemist")
            )
        })
        .ok_or_else(|| {
            CommandError::incomplete(
                "ARC_AUTHORITY_NOT_ASSERTED: current Legion or assigned Alchemist event required",
            )
        })?;
    let issuer = AuthorityInvocationProofIssuer::new(
        root.join(".audit/arcane/authority-invocations"),
        k.clone(),
        k.active_key_id()
            .map_err(|e| CommandError::incomplete(e.to_string()))?,
    );
    let proof = issuer
        .issue(
            event,
            b,
            "completion-claim",
            event["observedAuthority"].as_str().unwrap(),
        )
        .map_err(|e| CommandError::incomplete(e))?;
    let claim = json!({"schemaVersion":1,"kind":"arcane-terminal-operation-claim","claimId":format!("claim_{}",hash(&format!("{}:{}",b["runId"],canonical_digest(&outcome).unwrap_or_default()))),"invocationProofDigest":canonical_digest(&proof).unwrap_or_default(),"producerAuthority":event["observedAuthority"],"runId":b["runId"],"taskId":b["taskId"],"contractId":b["contractId"],"contractVersion":b["contractVersion"],"contractDigest":b["contractDigest"],"sourceRevision":seal(root,b)?["sourceRevision"],"outcomeSummaryDigest":canonical_digest(outcome.get("outcomeSummary").unwrap()).unwrap_or_default(),"artifactStateDigest":canonical_digest(outcome.get("artifactState").unwrap()).unwrap_or_default(),"turnCorrelationDigest":event["turnCorrelationDigest"],"expectedStopOrdinal":event["stopOrdinal"].as_u64().unwrap_or_default()+1});
    let dir = root.join(".audit/arcane/terminal-operations");
    fs::create_dir_all(&dir).map_err(super::io_error)?;
    let path = dir.join(format!(
        "{}.json",
        claim["claimId"].as_str().unwrap_or_default()
    ));
    if path.exists() {
        return Err(CommandError::incomplete("ARC_REPLAY_NONCE_SEEN"));
    }
    issuer
        .consume(&proof, Some(&canonical_digest(&claim).unwrap_or_default()))
        .map_err(|e| CommandError::incomplete(e))?;
    fs::write(path, serde_json::to_vec(&claim).map_err(super::io_error)?)
        .map_err(super::io_error)?;
    Ok(json!({"claimId":claim["claimId"],"invocationProofDigest":claim["invocationProofDigest"]}))
}
fn evidence(
    root: &Path,
    a: &[String],
    file: &str,
    b: &Value,
    s: &str,
    k: KeyRing,
) -> CommandResult {
    let report: Value = serde_json::from_slice(
        &fs::read(file)
            .map_err(|e| CommandError::usage(format!("invalid completion artifact: {e}")))?,
    )
    .map_err(|e| CommandError::usage(format!("invalid completion artifact: {e}")))?;
    let item = report.get("evidence").ok_or_else(|| {
        CommandError::usage("completion evidence artifact requires evidence object")
    })?;
    let se = seal(root, b)?;
    let criteria = se["contract"]["acceptanceCriteria"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let aid=item["acceptanceId"].as_str().ok_or_else(||CommandError::usage("ARC_SCHEMA_INVALID: evidence must map sealed acceptance to requirement, symbol, consumer, & surface"))?;
    if !criteria.iter().any(|x| x["id"].as_str() == Some(aid)) {
        return Err(CommandError::usage(
            "ARC_SCHEMA_INVALID: evidence acceptanceId is not sealed",
        ));
    }
    for key in [
        "requirementId",
        "productionSymbol",
        "liveConsumer",
        "acceptanceSurface",
    ] {
        if item[key].as_str().is_none_or(|x| x.is_empty()) {
            return Err(CommandError::usage("ARC_SCHEMA_INVALID: evidence must map sealed acceptance to requirement, symbol, consumer, & surface"));
        }
    }
    let es = events(root, s, &k)?;
    let event = es
        .iter()
        .rev()
        .find(|e| e["observedAuthority"] == "oracle")
        .ok_or_else(|| {
            CommandError::incomplete(
                "ARC_AUTHORITY_NOT_ASSERTED: current Oracle host event required",
            )
        })?;
    let issuer = AuthorityInvocationProofIssuer::new(
        root.join(".audit/arcane/authority-invocations"),
        k.clone(),
        k.active_key_id()
            .map_err(|e| CommandError::incomplete(e.to_string()))?,
    );
    let proof = issuer
        .issue(event, b, "completion-claim", "oracle")
        .map_err(|e| CommandError::incomplete(e))?;
    let obs = json!({"acceptanceId":aid,"requirementId":item["requirementId"],"productionSymbol":item["productionSymbol"],"liveConsumer":item["liveConsumer"],"acceptanceSurface":item["acceptanceSurface"],"contractVersion":b["contractVersion"],"contractDigest":b["contractDigest"],"sourceRevision":se["sourceRevision"],"authorityProofDigest":canonical_digest(&proof).unwrap_or_default(),"validUntil":item["validUntil"]});
    let deps = json!([]);
    let mut rec = json!({"schemaVersion":1,"kind":"legion-evidence-capability-receipt","evidenceId":format!("evidence_{}",hash(&format!("{}:{}",b["runId"],aid))),"runId":b["runId"],"taskId":b["taskId"],"contractId":b["contractId"],"producerAuthority":"oracle","capability":"oracle-acceptance-observation","observation":obs,"evidenceClass":"deterministic","sourceRevision":se["sourceRevision"],"dependsOn":deps,"observedAt":now()});
    rec["authentication"] = sign_record(
        &rec,
        &k,
        &k.active_key_id()
            .map_err(|e| CommandError::incomplete(e.to_string()))?,
        &EVIDENCE_FIELDS,
        None,
    )
    .map_err(|e| CommandError::incomplete(e.to_string()))?;
    let rs =
        ReceiptStore::new(root.join(".audit/arcane/receipts")).map_err(CommandError::incomplete)?;
    let digest = canonical_digest(&rec).unwrap_or_default();
    issuer
        .consume(&proof, Some(&digest))
        .map_err(|e| CommandError::incomplete(e))?;
    rs.append(&rec);
    Ok(json!({"evidenceId":rec["evidenceId"],"acceptanceId":aid}))
}
pub fn run(args: CommonArgs) -> CommandResult {
    let a = args
        .args
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let sub = a.first().map(String::as_str).ok_or_else(|| {
        CommandError::usage(
            "completion requires claim|evidence --file <outcome.json> [--session <id>]",
        )
    })?;
    if sub == "--help" || sub == "help" {
        return Ok(
            json!({"__raw":"Usage: legion completion claim|evidence --file <outcome.json> [--session <id>]\n"}),
        );
    }
    if !matches!(sub, "claim" | "evidence") {
        return Err(CommandError::usage("completion requires claim"));
    }
    let f = arg(&a, "--file").ok_or_else(|| {
        CommandError::usage(format!("completion {sub} requires --file <outcome.json>"))
    })?;
    let s = session(&a)?;
    let root = root()?;
    let k = ring(&a)?;
    let bs = SessionBindingStore::new(root.join(".audit/arcane/session-bindings"));
    let b = bs.get(&s).ok_or_else(|| {
        CommandError::incomplete("completion requires an authenticated session binding")
    })?;
    if b["contractId"].is_null() || b["taskId"].is_null() {
        return Err(CommandError::incomplete("ARC_NO_CONTRACT"));
    }
    if sub == "claim" {
        claim(&root, &a, &f, &b, &s, k)
    } else {
        evidence(&root, &a, &f, &b, &s, k)
    }
}
fn now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
