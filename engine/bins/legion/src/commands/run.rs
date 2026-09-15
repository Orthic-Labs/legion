//! Native, filesystem-backed `legion run` implementation.
use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_arcane::{
    BudgetGovernanceStore, ContractLifecycle, KeyRing, ReceiptStore, SessionBindingStore,
    TaskBudgetSealStore,
};
use legion_contracts::canonical_digest;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

fn arg(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|p| p[0] == n).map(|p| p[1].clone())
}
fn has(a: &[String], n: &str) -> bool {
    a.iter().any(|v| v == n)
}
fn session(a: &[String]) -> Result<String, CommandError> {
    arg(a,"--session").filter(|v|!v.is_empty()).or_else(||std::env::var("CODEX_THREAD_ID").ok()).or_else(||std::env::var("CLAUDE_CODE_SESSION_ID").ok()).or_else(||std::env::var("CLAUDE_SESSION_ID").ok()).or_else(||std::env::var("CODEX_SESSION_ID").ok()).filter(|v|!v.is_empty()).ok_or_else(||CommandError::usage("ARC_SESSION_UNKNOWN: no session id available (checked --session, then CODEX_THREAD_ID, CLAUDE_CODE_SESSION_ID, CLAUDE_SESSION_ID, CODEX_SESSION_ID) — never guessed"))
}
fn cwd() -> Result<PathBuf, CommandError> {
    std::env::current_dir().map_err(super::io_error)
}
fn ring() -> Result<KeyRing, CommandError> {
    let p = std::env::var_os("ARCANE_KEY_DIR").ok_or_else(|| {
        CommandError::integrity("ARC_AUTH_KEY_UNAVAILABLE: ARCANE_KEY_DIR is required")
    })?;
    KeyRing::load_dir(Path::new(&p)).map_err(|e| CommandError::integrity(e.to_string()))
}
fn git(root: &Path, a: &[&str]) -> Result<String, CommandError> {
    let o = Command::new("git")
        .args(a)
        .current_dir(root)
        .output()
        .map_err(super::io_error)?;
    if !o.status.success() {
        return Err(CommandError::incomplete(format!(
            "ARC_DELIVERY_GIT_INVALID: Git delivery check failed: {}",
            a.join(" ")
        )));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().into())
}
fn snapshot(root: &Path, head: &str) -> Result<String, CommandError> {
    let idx = std::env::temp_dir().join(format!("legion-index-{}", token()));
    let run = |a: &[&str]| -> Result<(), CommandError> {
        let o = Command::new("git")
            .args(a)
            .current_dir(root)
            .env("GIT_INDEX_FILE", &idx)
            .output()
            .map_err(super::io_error)?;
        if o.status.success() {
            Ok(())
        } else {
            Err(CommandError::incomplete(
                "ARC_DELIVERY_GIT_INVALID: Git delivery snapshot failed",
            ))
        }
    };
    let result = (|| {
        run(&["read-tree", head])?;
        run(&["add", "-A"])?;
        run(&["reset", "--", ".audit/arcane"])?;
        let o = Command::new("git")
            .arg("write-tree")
            .current_dir(root)
            .env("GIT_INDEX_FILE", &idx)
            .output()
            .map_err(super::io_error)?;
        if !o.status.success() {
            return Err(CommandError::incomplete(
                "ARC_DELIVERY_GIT_INVALID: Git delivery snapshot failed",
            ));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().into())
    })();
    let _ = fs::remove_file(idx);
    result
}
fn token() -> String {
    let mut h = Sha256::new();
    h.update(format!(
        "{}:{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    hex::encode(h.finalize())
}
fn hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}
fn seal(root: &Path, id: &str, v: u64) -> Result<Value, CommandError> {
    let p = legion_arcane::state_paths::state_file(
        &root.join(".audit/arcane/contract-seals"),
        "arcane.contract-seal.key.v1",
        &[id.into(), v.to_string()],
    )
    .map_err(|e| CommandError::integrity(e.to_string()))?;
    serde_json::from_slice(
        &fs::read(p).map_err(|_| {
            CommandError::usage("run open requires an exact sealed contract version")
        })?,
    )
    .map_err(|_| CommandError::incomplete("ARC_STORE_CORRUPT: unreadable contract seal"))
}
fn manifest_path(root: &Path, o: &Value) -> PathBuf {
    root.join(".audit/arcane/delivery/manifests").join(format!(
        "{}.json",
        hash(&format!(
            "{}\0{}\0{}",
            o["sessionId"], o["runId"], o["taskId"]
        ))
    ))
}
fn delivery_open(
    cwd: &Path,
    paths: &[String],
    owner: &Value,
    ro: bool,
) -> Result<Value, CommandError> {
    let paths = if paths.is_empty() {
        vec![cwd.to_string_lossy().into()]
    } else {
        paths.to_vec()
    };
    let mut repos = Vec::new();
    for p in paths {
        let r = PathBuf::from(git(Path::new(&p), &["rev-parse", "--show-toplevel"])?);
        let common = fs::canonicalize(r.join(git(&r, &["rev-parse", "--git-common-dir"])?))
            .unwrap_or_else(|_| r.join(".git"));
        let primary = fs::canonicalize(&r).unwrap_or(r.clone());
        let rf = git(&primary, &["symbolic-ref", "-q", "HEAD"])?;
        let head = git(&primary, &["rev-parse", "HEAD"])?;
        let tree = snapshot(&primary, &head)?;
        let mode = if ro { "read-only" } else { "write" };
        let lease = token();
        let acq = if ro {
            Value::String(hash(&format!(
                "{}\0{}\0{}\0{}",
                owner["sessionId"],
                owner["runId"],
                owner["taskId"],
                common.display()
            )))
        } else {
            Value::Null
        };
        let repo = json!({"root":primary,"commonDir":common,"primaryRoot":primary,"canonicalRef":rf,"head":head,"snapshotTree":tree,"mode":mode,"leaseToken":lease,"acquisitionKey":acq});
        let d = primary.join(".audit/arcane/delivery");
        if ro {
            let ad = d.join("acquisitions");
            fs::create_dir_all(&ad).map_err(super::io_error)?;
            fs::write(
                ad.join(format!("{}.json", acq.as_str().unwrap_or_default())),
                serde_json::to_vec(&json!({"owner":owner,"token":lease,"metadata":repo}))
                    .map_err(super::io_error)?,
            )
            .map_err(super::io_error)?
        } else {
            fs::create_dir_all(&d).map_err(super::io_error)?;
            let lp = d.join("lease.json");
            if lp.exists() {
                let old: Value = serde_json::from_slice(&fs::read(&lp).map_err(super::io_error)?)
                    .map_err(super::io_error)?;
                if old["sessionId"] != owner["sessionId"]
                    || old["runId"] != owner["runId"]
                    || old["taskId"] != owner["taskId"]
                    || old["metadata"]["root"] != repo["root"]
                {
                    return Err(CommandError::incomplete(
                        "ARC_INTEGRATION_OWNER_CONFLICT: another run owns repository integration",
                    ));
                }
            } else {
                fs::write(lp,serde_json::to_vec(&json!({"sessionId":owner["sessionId"],"runId":owner["runId"],"taskId":owner["taskId"],"repository":repo["root"],"token":lease,"metadata":repo})).map_err(super::io_error)?).map_err(super::io_error)?
            }
        }
        repos.push(repo)
    }
    Ok(json!({"repositories":repos}))
}
fn validate_delivery(d: &Value, owner: &Value) -> Result<(), CommandError> {
    for r in d["repositories"]
        .as_array()
        .ok_or_else(|| CommandError::incomplete("ARC_DELIVERY_METADATA_MISMATCH"))?
    {
        if r["mode"] == "write" {
            let p = Path::new(r["primaryRoot"].as_str().unwrap_or_default())
                .join(".audit/arcane/delivery/lease.json");
            let l: Value = serde_json::from_slice(
                &fs::read(p).map_err(|_| CommandError::incomplete("ARC_DELIVERY_LEASE_MISSING"))?,
            )
            .map_err(|_| CommandError::incomplete("ARC_DELIVERY_METADATA_MISMATCH"))?;
            if l["sessionId"] != owner["sessionId"]
                || l["runId"] != owner["runId"]
                || l["taskId"] != owner["taskId"]
                || l["token"] != r["leaseToken"]
            {
                return Err(CommandError::incomplete(
                    "ARC_DELIVERY_OWNER_MISMATCH: delivery lease owner differs",
                ));
            }
        }
    }
    Ok(())
}
fn close_delivery(d: &Value, owner: &Value, disposition: &str) -> Result<Vec<Value>, CommandError> {
    validate_delivery(d, owner)?;
    let mut out = Vec::new();
    for r in d["repositories"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let root = Path::new(r["primaryRoot"].as_str().unwrap_or_default());
        let head = git(root, &["rev-parse", "HEAD"])?;
        let tree = snapshot(root, &head)?;
        let changed = tree != r["snapshotTree"];
        if r["mode"] == "read-only" && changed {
            return Err(CommandError::incomplete("ARC_DELIVERY_READ_ONLY_MUTATED"));
        };
        let state = if !changed {
            "clean"
        } else if disposition == "complete" {
            "integrated"
        } else {
            "archived"
        };
        out.push(json!({"repository":root,"commonDir":r["commonDir"],"baselineTree":r["snapshotTree"],"closeTree":tree,"canonicalRef":r["canonicalRef"],"commit":head,"reachable":state=="integrated","disposition":disposition,"state":state,"patch":Value::Null,"leaseToken":r["leaseToken"]}));
    }
    Ok(out)
}
fn release_delivery(d: &Value) {
    for r in d["repositories"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let root = Path::new(r["primaryRoot"].as_str().unwrap_or_default());
        let p = root.join(".audit/arcane/delivery");
        if r["mode"] == "write" {
            let _ = fs::remove_file(p.join("lease.json"));
        } else {
            let _ = fs::remove_file(p.join("acquisitions").join(format!(
                "{}.json",
                r["acquisitionKey"].as_str().unwrap_or_default()
            )));
        }
    }
}
pub async fn run(args: CommonArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    let a = args
        .args
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let sub = a.first().map(String::as_str).ok_or_else(|| {
        CommandError::usage(
            "run requires a subcommand: open|close|suspend|supersede|repair (got <none>)",
        )
    })?;
    match sub {
        "open" => open(&a[1..]),
        "close" => close(&a[1..]),
        "suspend" | "supersede" | "repair" => lifecycle(sub, &a[1..]),
        _ => Err(CommandError::usage(format!(
            "run requires a subcommand: open|close|suspend|supersede|repair (got {sub})"
        ))),
    }
}
fn open(a: &[String]) -> CommandResult {
    let c = arg(a, "--contract")
        .filter(|v| v.starts_with("EC-") && v[3..].parse::<u64>().is_ok())
        .ok_or_else(|| {
            let got = arg(a, "--contract").unwrap_or_else(|| "<none>".into());
            CommandError::usage(format!("run open requires --contract <EC-#> (got {got})"))
        })?;
    let v = arg(a, "--version")
        .and_then(|x| x.parse::<u64>().ok())
        .filter(|x| *x > 0)
        .ok_or_else(|| CommandError::usage("run open requires --version <positive integer>"))?;
    let t = arg(a, "--task");
    if let Some(x) = &t {
        if !x.starts_with("T-") || x[2..].split('.').any(|n| n.parse::<u64>().is_err()) {
            return Err(CommandError::usage(format!(
                "run open --task must match T-#(.#)* (got {x})"
            )));
        }
    }
    let s = session(a)?;
    let adapter = arg(a, "--adapter").unwrap_or_else(|| "claude-code".into());
    if !["claude-code", "codex"].contains(&adapter.as_str()) {
        return Err(CommandError::usage(format!(
            "run open unknown adapter '{adapter}'"
        )));
    }
    let root = cwd()?;
    let seal = seal(&root, &c, v)?;
    let head = git(&root, &["rev-parse", "HEAD"])?;
    if seal["sourceRevision"].as_str() != Some(head.as_str()) {
        return Err(CommandError::incomplete(
            "ARC_CONTRACT_SOURCE_STALE: sealed contract sourceRevision differs from current HEAD",
        ));
    }
    let task = t.as_deref().ok_or_else(|| {
        CommandError::incomplete("ARC_BINDING_MISMATCH: contracted run requires a task budget")
    })?;
    let key_dir = std::env::var_os("ARCANE_KEY_DIR").ok_or_else(|| {
        CommandError::incomplete(
            "ARC_AUTH_KEY_UNAVAILABLE: run budget verification requires ARCANE_KEY_DIR",
        )
    })?;
    let budget_ring = KeyRing::load_dir(Path::new(&key_dir))
        .map_err(|e| CommandError::incomplete(e.to_string()))?;
    let budget = BudgetGovernanceStore::new(
        root.join(".audit/arcane/budget-governance"),
        budget_ring.clone(),
    )
    .require(&c, v as u32)
    .map_err(|e| CommandError::incomplete(e.to_string()))?;
    let task_seal =
        TaskBudgetSealStore::new(root.join(".audit/arcane/task-budget-seals"), budget_ring)
            .require_version(&c, task, &v.to_string())
            .map_err(|e| CommandError::incomplete(e.to_string()))?;
    if budget["contractDigest"] != seal["contractDigest"]
        || task_seal["contractId"] != c
        || task_seal["contractVersion"] != v
        || task_seal["contractDigest"] != seal["contractDigest"]
    {
        return Err(CommandError::incomplete(
            "ARC_BINDING_MISMATCH: budget does not exactly bind this contract",
        ));
    }
    let bindings = SessionBindingStore::new(root.join(".audit/arcane/session-bindings"));
    let old = bindings
        .ensure(&s)
        .ok_or_else(|| CommandError::internal("run open: session binding store is unavailable"))?;
    if old.get("delivery").is_some()
        && (old["contractId"] != c
            || old["taskId"] != t.clone().map(Value::String).unwrap_or(Value::Null))
    {
        return Err(CommandError::incomplete(
            "ARC_INTEGRATION_OWNER_CONFLICT: active delivery belongs to another contract/task",
        ));
    }
    let owner = json!({"sessionId":s,"runId":old["runId"],"taskId":t.clone()});
    let reps = a
        .iter()
        .enumerate()
        .filter(|(_, x)| *x == "--repo")
        .filter_map(|(i, _)| a.get(i + 1).cloned())
        .collect::<Vec<_>>();
    let mut d = if let Some(existing) = old.get("delivery") {
        let requested = if reps.is_empty() {
            vec![root.to_string_lossy().into_owned()]
        } else {
            reps.clone()
        };
        let current = existing["repositories"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ro = has(a, "--read-only");
        if requested.len() != current.len()
            || requested.iter().zip(current.iter()).any(|(p, r)| {
                let resolved =
                    git(Path::new(p), &["rev-parse", "--show-toplevel"]).unwrap_or_default();
                resolved != r["root"].as_str().unwrap_or_default()
                    || r["mode"] != if ro { "read-only" } else { "write" }
            })
        {
            return Err(CommandError::incomplete("ARC_INTEGRATION_OWNER_CONFLICT: requested repository set differs from active delivery"));
        }
        existing.clone()
    } else {
        delivery_open(&root, &reps, &owner, has(a, "--read-only"))?
    };
    let mp = manifest_path(&root, &owner);
    fs::create_dir_all(mp.parent().unwrap()).map_err(super::io_error)?;
    let m = if mp.exists() {
        serde_json::from_slice(&fs::read(&mp).map_err(super::io_error)?).map_err(super::io_error)?
    } else {
        let x = json!({"owner":owner,"repositories":d["repositories"],"token":token()});
        fs::write(&mp, serde_json::to_vec(&x).map_err(super::io_error)?)
            .map_err(super::io_error)?;
        x
    };
    d["manifest"] = json!({"token":m["token"],"digest":canonical_digest(&m).map_err(|e|CommandError::integrity(e.to_string()))?});
    let mut b = old.as_object().cloned().unwrap_or_default();
    b.insert("taskId".into(), t.map(Value::String).unwrap_or(Value::Null));
    b.insert("contractId".into(), Value::String(c));
    b.insert("contractVersion".into(), Value::from(v));
    b.insert("contractDigest".into(), seal["contractDigest"].clone());
    b.insert("delivery".into(), d);
    let stored = bindings.put(&s, &Value::Object(b)).ok_or_else(|| {
        CommandError::internal("run open: failed to persist the contract/task binding")
    })?;
    Ok(
        json!({"kind":"legion-run-binding","sessionId":s,"runId":stored["runId"],"taskId":stored["taskId"],"contractId":stored["contractId"],"contractVersion":stored["contractVersion"],"contractDigest":stored["contractDigest"],"delivery":stored["delivery"]}),
    )
}
fn close(a: &[String]) -> CommandResult {
    let s = session(a)?;
    let root = cwd()?;
    let bs = SessionBindingStore::new(root.join(".audit/arcane/session-bindings"));
    let b = bs.get(&s).ok_or_else(|| {
        CommandError::usage("run close: no binding exists for this session — nothing to close")
    })?;
    if b["lifecycle"]["state"] == "suspended" {
        return Err(CommandError::incomplete("ARC_BINDING_MISMATCH: suspended binding requires lifecycle repair or supersede before release"));
    }
    let disp = arg(a, "--disposition").unwrap_or_else(|| "complete".into());
    if !["complete", "archive"].contains(&disp.as_str()) {
        return Err(CommandError::usage(
            "run close --disposition must be complete or archive",
        ));
    }
    if !b["contractId"].is_null() && b.get("delivery").is_none() {
        return Err(CommandError::incomplete(
            "ARC_DELIVERY_METADATA_MISSING: contracted binding lacks delivery metadata",
        ));
    }
    let rs =
        ReceiptStore::new(root.join(".audit/arcane/receipts")).map_err(CommandError::incomplete)?;
    if disp == "complete" {
        let criteria = seal(
            &root,
            b["contractId"].as_str().unwrap_or_default(),
            b["contractVersion"].as_u64().unwrap_or_default(),
        )
            .ok()
            .and_then(|v| v["contract"]["acceptanceCriteria"].as_array().cloned())
            .unwrap_or_default();
        let receipts = rs.list();
        for criterion in criteria {
            let id = criterion["id"].as_str().unwrap_or_default();
            if !receipts.iter().any(|r| {
                r["kind"] == "legion-evidence-capability-receipt"
                    && r["runId"] == b["runId"]
                    && r["observation"]["acceptanceId"] == id
            }) {
                return Err(CommandError::incomplete(
                    "ARC_EVIDENCE_INSUFFICIENT: completion acceptance evidence is missing",
                ));
            }
        }
    }
    let owner = json!({"sessionId":s,"runId":b["runId"],"taskId":b["taskId"]});
    let d = b
        .get("delivery")
        .ok_or_else(|| CommandError::incomplete("ARC_DELIVERY_METADATA_MISSING"))?;
    let ev = close_delivery(d, &owner, &disp)?;
    for x in &ev {
        let mut r = json!({"schemaVersion":1,"kind":"arcane-delivery-receipt","sessionId":s,"runId":b["runId"],"taskId":b["taskId"],"contractId":b["contractId"],"contractVersion":b["contractVersion"],"contractDigest":b["contractDigest"],"closedAt":now()});
        for (k, v) in x.as_object().unwrap() {
            r[k] = v.clone()
        }
        rs.append(&r);
    }
    let terminal = json!({"schemaVersion":1,"kind":"legion-run-close-receipt","runId":b["runId"],"taskId":b["taskId"],"contractId":b["contractId"],"contractVersion":b["contractVersion"],"contractDigest":b["contractDigest"],"sessionId":s,"finalClaimState":"passed","completionCode":if disp=="archive"{"ARC_ARCHIVE"}else{"ARC_COMPLETION_PASSED"},"enforcementHealth":if disp=="archive"{"not-applicable"}else{"strong"},"deliveryDisposition":disp,"deliveryEvidence":ev,"closedAt":now()});
    let stamp = rs.append(&terminal);
    release_delivery(d);
    let mut clear = b.as_object().cloned().unwrap_or_default();
    for k in [
        "taskId",
        "contractId",
        "contractVersion",
        "contractDigest",
        "delivery",
        "lifecycle",
    ] {
        clear.insert(k.into(), Value::Null);
    }
    bs.put(&s, &Value::Object(clear));
    let mut close_receipt = terminal.as_object().cloned().unwrap_or_default();
    close_receipt.extend(stamp.as_object().cloned().unwrap_or_default());
    Ok(
        json!({"kind":"legion-run-binding","sessionId":s,"runId":b["runId"],"taskId":Value::Null,"contractId":Value::Null,"contractVersion":Value::Null,"contractDigest":Value::Null,"closeReceipt":Value::Object(close_receipt)}),
    )
}
fn lifecycle(action: &str, a: &[String]) -> CommandResult {
    let s = session(a)?;
    // Node loads host authentication before validating action-specific inputs.
    // This preserves fail-closed ARC_AUTH_KEY_UNAVAILABLE precedence.
    let k = ring()?;
    let tx = arg(a, "--transaction")
        .ok_or_else(|| CommandError::usage(format!("run {action} requires --transaction <id>")))?;
    let root = cwd()?;
    let id = k
        .active_key_id()
        .map_err(|e| CommandError::incomplete(e.to_string()))?;
    let lc = ContractLifecycle::new(
        root.join(".audit/arcane/contract-transitions"),
        SessionBindingStore::new(root.join(".audit/arcane/session-bindings")),
        k,
        id,
    );
    let target = if action == "supersede" {
        Some((
            arg(a, "--contract").ok_or_else(|| {
                CommandError::usage(
                    "run supersede requires --contract <EC-#> --version <positive integer>",
                )
            })?,
            arg(a, "--version")
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| {
                    CommandError::usage(
                        "run supersede requires --contract <EC-#> --version <positive integer>",
                    )
                })?,
            arg(a, "--task"),
        ))
    } else {
        None
    };
    let r = if action == "repair" {
        lc.repair(&s)
    } else {
        lc.transition(
            action,
            &s,
            &tx,
            target,
            &root.join(".audit/arcane/contract-seals"),
        )
    };
    Ok(
        json!({"kind":"legion-contract-transition","receipt":r.map_err(|e|CommandError::incomplete(e))?}),
    )
}
fn now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
