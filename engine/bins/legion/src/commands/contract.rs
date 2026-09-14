//! Authenticated `legion contract seal` producer.

use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_arcane::{
    sign_record, state_paths::state_file, state_root, BudgetGovernanceStore, KeyRing,
    TaskBudgetSealStore,
    AMENDED_BUDGET_BOUND_FIELDS, BUDGET_AMENDMENT_BOUND_FIELDS, BUDGET_BOUND_FIELDS,
};
use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let day = seconds / 86400;
    let rem = seconds % 86400;
    let z = day as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}
fn digest_for(domain: &str, values: &[String]) -> Result<String, CommandError> {
    canonical_digest(&json!({"domain":domain,"values":values}))
        .map_err(|e| CommandError::integrity(e.to_string()))
}
fn option(argv: &[String], name: &str) -> Result<Option<String>, CommandError> {
    let mut out = None;
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == name {
            let v = argv
                .get(i + 1)
                .filter(|x| !x.starts_with('-'))
                .ok_or_else(|| CommandError::usage(format!("option '{name}' argument missing")))?;
            out = Some(v.clone());
            i += 1;
        } else if argv[i].starts_with('-') {
            let known = [
                "--file",
                "--agent",
                "--session",
                "--adapter",
                "--key-dir",
                "--reachability",
                "--task-budgets",
            ];
            if !known.contains(&argv[i].as_str()) {
                return Err(CommandError::usage(format!("Unknown option: {}", argv[i])));
            }
        }
        i += 1;
    }
    Ok(out)
}
fn read_json(path: &str, label: &str) -> Result<Value, CommandError> {
    let b = fs::read(path).map_err(|e| {
        CommandError::usage(format!("contract seal cannot read --{label} {path}: {e}"))
    })?;
    serde_json::from_slice(&b).map_err(|e| {
        CommandError::usage(format!("contract seal cannot parse --{label} {path}: {e}"))
    })
}
fn reachability_allowed(lifecycle: &Value) -> bool {
    let requirements = lifecycle
        .get("requirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let recovery = lifecycle
        .get("recoveryPaths")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let capabilities = lifecycle
        .get("providerCapabilities")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    requirements.iter().all(|r| {
        let steps = [
            "producer",
            "durableStore",
            "authenticatedPersistence",
            "verifier",
            "completionConsumer",
            "closePath",
        ];
        if steps.iter().any(|k| {
            r.get(*k)
                .map_or(false, |v| v.is_null() || v == &json!(false))
                || r.get(*k).is_none()
        }) {
            return false;
        }
        let producer = r.get("producer").and_then(Value::as_str);
        if producer.is_some()
            && (producer == r.get("verifier").and_then(Value::as_str)
                || producer == r.get("completionConsumer").and_then(Value::as_str))
        {
            return false;
        }
        if ["selfAttested", "fixtureOnly", "genericReceipt"]
            .iter()
            .any(|k| r.get(*k) == Some(&json!(true)))
        {
            return false;
        }
        if let Some(provider) = r.get("externalProvider").and_then(Value::as_str) {
            let capability = capabilities
                .iter()
                .find(|c| c.get("providerId").and_then(Value::as_str) == Some(provider));
            if capability.is_none()
                || [
                    "machineReadable",
                    "gateable",
                    "downloadable",
                    "trustedRetrieval",
                    "trajectoryBindable",
                ]
                .iter()
                .any(|k| capability.and_then(|v| v.get(*k)) != Some(&json!(true)))
            {
                return false;
            }
            if capability
                .and_then(|v| v.get("sensitivity"))
                .and_then(Value::as_str)
                == Some("sensitive")
                && (capability
                    .and_then(|v| v.get("retention"))
                    .map_or(true, Value::is_null)
                    || capability
                        .and_then(|v| v.get("deletionOwner"))
                        .map_or(true, Value::is_null))
            {
                return false;
            }
        }
        recovery.iter().any(|p| {
            p.get("requirementId") == r.get("id")
                && p.get("authenticated") == Some(&json!(true))
                && p.get("closePath") == Some(&json!(true))
        })
    })
}
fn issue(code: &str, msg: impl Into<String>) -> CommandError {
    let m = msg.into();
    match code {
        "ARC_SCHEMA_INVALID"
        | "ARC_CONTRACT_NOT_EXECUTABLE"
        | "ARC_UNSOUND_SEAL"
        | "ARC_BINDING_MISMATCH" => CommandError::usage(format!("{code}: {m}")),
        "ARC_AUTH_KEY_UNAVAILABLE"
        | "ARC_AUTHORITY_NOT_ASSERTED"
        | "ARC_CONTRACT_VERSION_MISMATCH" => CommandError::incomplete(format!("{code}: {m}")),
        _ => CommandError::internal(format!("{code}: {m}")),
    }
}
fn is_string(v: Option<&Value>, min: usize) -> bool {
    v.and_then(Value::as_str)
        .map_or(false, |s| s.chars().count() >= min)
}
fn id(s: &str, p: &str) -> bool {
    s.strip_prefix(p).map_or(false, |x| {
        !x.is_empty() && x.chars().all(|c| c.is_ascii_digit())
    })
}
fn typ(v: &Value) -> &'static str {
    if v.is_boolean() {
        "boolean"
    } else if v.is_number() {
        "number"
    } else if v.is_array() || v.is_object() {
        "object"
    } else {
        "string"
    }
}
fn digest_shape(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).map_or(false, |s| {
        s.len() == 71 && s.starts_with("sha256:") && s[7..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}

/// Structural execution-contract checks plus Node's executable invariants.
fn executable_errors(c: &Value) -> Vec<(String, String, String)> {
    let mut e: Vec<(String, String, String)> = Vec::new();
    let Some(o) = c.as_object() else {
        return vec![(
            "INPUT_NOT_OBJECT".into(),
            "$".into(),
            "contract must be a plain object".into(),
        )];
    };
    let req = [
        "schemaVersion",
        "kind",
        "contractId",
        "version",
        "sourceRevision",
        "objective",
        "currentState",
        "desiredState",
        "requirements",
        "decisions",
        "invariants",
        "nonGoals",
        "scope",
        "artifacts",
        "tasks",
        "dependencies",
        "acceptanceCriteria",
        "declaredChecks",
        "evidenceRequirements",
        "authorizedEffectClasses",
        "repairLatitude",
        "stopConditions",
        "escalationConditions",
        "rollback",
        "openQuestions",
    ];
    let known = [
        "schemaVersion",
        "kind",
        "contractId",
        "version",
        "sourceRevision",
        "advisoryProfile",
        "objective",
        "currentState",
        "desiredState",
        "requirements",
        "decisions",
        "invariants",
        "nonGoals",
        "scope",
        "artifacts",
        "tasks",
        "dependencies",
        "acceptanceCriteria",
        "declaredChecks",
        "evidenceRequirements",
        "authorizedEffectClasses",
        "repairLatitude",
        "stopConditions",
        "escalationConditions",
        "rollback",
        "openQuestions",
        "budget",
    ];
    for key in o.keys() {
        if !known.contains(&key.as_str()) {
            e.push((
                "SCHEMA".into(),
                format!("$.{key}"),
                format!("$.{key}: must NOT have additional properties"),
            ));
        }
    }
    for k in req {
        if !o.contains_key(k) {
            e.push((
                "SCHEMA".into(),
                format!("$.{k}"),
                format!("$.{k}: is required"),
            ));
        }
    }
    if o.get("schemaVersion") != Some(&json!(1)) {
        e.push((
            "SCHEMA".into(),
            "$.schemaVersion".into(),
            "schemaVersion must be 1".into(),
        ));
    }
    if o.get("kind").and_then(Value::as_str) != Some("legion-execution-contract") {
        e.push((
            "SCHEMA".into(),
            "$.kind".into(),
            "kind must be legion-execution-contract".into(),
        ));
    }
    if !o
        .get("contractId")
        .and_then(Value::as_str)
        .map_or(false, |s| id(s, "EC-"))
    {
        e.push((
            "SCHEMA".into(),
            "$.contractId".into(),
            "contractId must match ^EC-\\d+$".into(),
        ));
    }
    if o.get("version")
        .and_then(Value::as_u64)
        .map_or(true, |v| v < 1)
    {
        e.push((
            "SCHEMA".into(),
            "$.version".into(),
            "version must be a positive integer".into(),
        ));
    }
    if !is_string(o.get("sourceRevision"), 7) {
        e.push((
            "SCHEMA".into(),
            "$.sourceRevision".into(),
            "sourceRevision must be a string of at least 7 characters".into(),
        ));
    }
    for k in ["objective", "currentState", "desiredState"] {
        if !is_string(o.get(k), 1) {
            e.push((
                "SCHEMA".into(),
                format!("$.{k}"),
                format!("{k} must be a non-empty string"),
            ));
        }
    }
    for k in [
        "requirements",
        "decisions",
        "invariants",
        "nonGoals",
        "tasks",
        "dependencies",
        "acceptanceCriteria",
        "declaredChecks",
        "evidenceRequirements",
        "authorizedEffectClasses",
        "repairLatitude",
        "stopConditions",
        "escalationConditions",
        "rollback",
        "openQuestions",
    ] {
        if !o.get(k).map_or(false, Value::is_array) {
            e.push((
                "SCHEMA".into(),
                format!("$.{k}"),
                format!("{k} must be an array"),
            ));
        }
    }
    for (key, id_prefix) in [("requirements", "R-"), ("decisions", "D-"), ("invariants", "I-"), ("nonGoals", "NG-"), ("acceptanceCriteria", "AC-")] {
        if let Some(items) = o.get(key).and_then(Value::as_array) {
            for (i, item) in items.iter().enumerate() {
                if item.as_object().is_none() || !is_string(item.get("id"), 1) || !is_string(item.get("statement"), 1) {
                    e.push(("SCHEMA".into(), format!("$.{key}[{i}]"), format!("$.{key}[{i}]: invalid {key} entry")));
                } else if !item["id"].as_str().map_or(false, |s| id(s, id_prefix)) {
                    e.push(("SCHEMA".into(), format!("$.{key}[{i}].id"), format!("$.{key}[{i}].id: invalid identifier")));
                }
            }
        }
    }
    let scope = o.get("scope").and_then(Value::as_object);
    for k in ["own", "read", "forbidden"] {
        if scope.map_or(true, |x| !x.get(k).map_or(false, Value::is_array)) {
            e.push((
                "SCHEMA".into(),
                format!("$.scope.{k}"),
                format!("scope.{k} must be an array"),
            ));
        }
    }
    let arts = o.get("artifacts").and_then(Value::as_object);
    for k in ["exact", "bounded"] {
        if arts.map_or(true, |x| !x.get(k).map_or(false, Value::is_array)) {
            e.push((
                "SCHEMA".into(),
                format!("$.artifacts.{k}"),
                format!("artifacts.{k} must be an array"),
            ));
        }
    }
    if o.get("openQuestions")
        .and_then(Value::as_array)
        .map_or(true, |a| !a.is_empty())
    {
        e.push((
            "EXEC_OPEN_QUESTIONS_NONEMPTY".into(),
            "$.openQuestions".into(),
            "execution contract has open questions".into(),
        ));
    }
    for (lat, k) in [("exact", "exact"), ("bounded", "bounded")] {
        if let Some(items) = arts.and_then(|a| a.get(k)).and_then(Value::as_array) {
            for (i, u) in items.iter().enumerate() {
                let p = format!("$.artifacts.{k}[{i}]");
                let label = u.get("id").and_then(Value::as_str).unwrap_or(&p);
                for required in ["id", "path", "latitude"] {
                    if u.get(required).is_none() {
                        e.push((
                            "SCHEMA".into(),
                            format!("{p}.{required}"),
                            format!("{p}.{required}: is required"),
                        ));
                    }
                }
                if !matches!(
                    u.get("latitude").and_then(Value::as_str),
                    Some("EXACT" | "BOUNDED")
                ) {
                    e.push((
                        "SCHEMA".into(),
                        format!("{p}.latitude"),
                        format!("{p}.latitude: must be EXACT or BOUNDED"),
                    ));
                }
                if lat == "exact" {
                    match u.get("content") {
                        None | Some(Value::Null) => e.push((
                            "EXEC_EXACT_CONTENT_NULL".into(),
                            format!("{p}.content"),
                            format!("EXACT artifact {label} requires content"),
                        )),
                        Some(v) if !v.is_string() => e.push((
                            "EXEC_EXACT_CONTENT_TYPE".into(),
                            format!("{p}.content"),
                            format!(
                                "EXACT artifact {label} content must be string; got {}",
                                typ(v)
                            ),
                        )),
                        _ => {}
                    }
                } else {
                    if u.get("locked")
                        .and_then(Value::as_array)
                        .map_or(true, |a| a.is_empty())
                    {
                        e.push((
                            "EXEC_BOUNDED_LOCKED_EMPTY".into(),
                            format!("{p}.locked"),
                            format!("BOUNDED artifact {label} requires locked and freedom"),
                        ));
                    }
                    if u.get("freedom")
                        .and_then(Value::as_array)
                        .map_or(true, |a| a.is_empty())
                    {
                        e.push((
                            "EXEC_BOUNDED_FREEDOM_EMPTY".into(),
                            format!("{p}.freedom"),
                            format!("BOUNDED artifact {label} requires locked and freedom"),
                        ));
                    }
                }
            }
        }
    }
    if let Some(ds) = o.get("dependencies").and_then(Value::as_array) {
        for (i, d) in ds.iter().enumerate() {
            if d.get("reason").and_then(Value::as_str) == Some("shared-mutable-resource")
                && d.get("resourceKey")
                    .map_or(true, |v| v.is_null() || v.as_str() == Some(""))
            {
                e.push((
                    "EXEC_RESOURCE_KEY_MISSING".into(),
                    format!("$.dependencies[{i}].resourceKey"),
                    "shared mutable dependency requires resourceKey".into(),
                ));
            }
        }
    }
    if let Some(tasks) = o.get("tasks").and_then(Value::as_array) {
        for (i, task) in tasks.iter().enumerate() {
            if !task.as_str().map_or(false, |s| {
                let tail = s.strip_prefix("T-").unwrap_or("");
                !tail.is_empty()
                    && tail
                        .split('.')
                        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
            }) {
                e.push((
                    "SCHEMA".into(),
                    format!("$.tasks[{i}]"),
                    format!("$.tasks[{i}]: invalid task id"),
                ));
            }
        }
    }
    let mut ids = Vec::new();
    for k in [
        "requirements",
        "decisions",
        "invariants",
        "nonGoals",
        "acceptanceCriteria",
    ] {
        if let Some(a) = o.get(k).and_then(Value::as_array) {
            for x in a {
                if let Some(v) = x.get("id").and_then(Value::as_str) {
                    ids.push((v.to_string(), k.to_string()));
                }
            }
        }
    }
    if let Some(a) = o.get("tasks").and_then(Value::as_array) {
        for x in a {
            if let Some(v) = x.as_str() {
                ids.push((v.to_string(), "tasks".into()));
            }
        }
    }
    let mut seen = std::collections::BTreeMap::new();
    for (v, w) in ids {
        if let Some(prev) = seen.insert(v.clone(), w.clone()) {
            e.push((
                "EXEC_ID_NOT_UNIQUE".into(),
                format!("$.{prev}[*].id"),
                format!("execution contract ids must be unique: {v} appears in {prev} and {w}"),
            ));
        }
    }
    e.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    e
}

fn binding(
    cwd: &Path,
    adapter: &str,
    session: &str,
    agent: Option<&str>,
) -> Result<Value, CommandError> {
    let root = cwd.join(".audit/arcane/authority-bindings");
    let sd = digest_for(
        "arcane.authority.session.v1",
        &[adapter.into(), session.into()],
    )?;
    let wanted = agent
        .map(|a| {
            digest_for(
                "arcane.authority.binding-key.v1",
                &[adapter.into(), session.into(), a.into()],
            )
        })
        .transpose()?;
    let mut rows = Vec::new();
    let it = match fs::read_dir(&root) {
        Ok(x) => x,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(issue(
                "ARC_AUTHORITY_NOT_ASSERTED",
                if agent.is_some() {
                    "no observed authority binding for requested agent"
                } else {
                    "no observed Sage or Legion binding in this session"
                },
            ))
        }
        Err(e) => return Err(issue("ARC_AUTHORITY_NOT_ASSERTED", e.to_string())),
    };
    for x in it.flatten() {
        if x.path().extension().and_then(|z| z.to_str()) != Some("json") {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<Value>(&fs::read(x.path()).unwrap_or_default()) else {
            continue;
        };
        if v.get("kind").and_then(Value::as_str) != Some("arcane-authority-binding")
            || v.get("adapter").and_then(Value::as_str) != Some(adapter)
            || v.get("sessionIdDigest").and_then(Value::as_str) != Some(sd.as_str())
        {
            continue;
        }
        if let Some(w) = &wanted {
            if x.file_name().to_string_lossy().trim_end_matches(".json")
                != w.trim_start_matches("sha256:")
            {
                continue;
            }
        }
        rows.push(v)
    }
    if agent.is_none() {
        rows.retain(|x| matches!(x["authority"].as_str(), Some("legion" | "sage")))
    }
    rows.sort_by_key(|x| {
        x.get("observedAt")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    rows.pop().ok_or_else(|| {
        issue(
            "ARC_AUTHORITY_NOT_ASSERTED",
            if agent.is_some() {
                "no observed authority binding for requested agent"
            } else {
                "no observed Sage or Legion binding in this session"
            },
        )
    })
}

fn verify_codex(
    cwd: &Path,
    ring: &KeyRing,
    adapter: &str,
    session: &str,
    b: &Value,
) -> Result<(), CommandError> {
    if adapter != "codex" {
        return Ok(());
    }
    let root = state_root(cwd).join("host-events");
    let mut rs: Vec<Value> = Vec::new();
    if root.is_dir() {
        for x in fs::read_dir(&root).map_err(super::io_error)?.flatten() {
            let n = x.file_name().to_string_lossy().into_owned();
            if n.len() == 21 && n.ends_with(".json") && n[..16].chars().all(|c| c.is_ascii_digit())
            {
                if let Ok(v) = serde_json::from_slice(&fs::read(x.path()).unwrap_or_default()) {
                    rs.push(v)
                }
            }
        }
    }
    rs.sort_by_key(|x| x["eventSequence"].as_u64().unwrap_or(0));
    let fields = [
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
    let mut prior = None;
    for (i, r) in rs.iter().enumerate() {
        let v = legion_arcane::receipt_auth::verify_record(
            r,
            r.get("authentication"),
            ring,
            &fields,
            &Map::new(),
            None,
        )
        .map_err(|e| issue(e.code(), e.to_string()))?;
        let pd = prior
            .as_ref()
            .map(|p: &Value| canonical_digest(p).ok())
            .flatten();
        if !v.allowed
            || r["eventSequence"] != json!((i + 1) as u64)
            || r.get("previousDigest").and_then(Value::as_str) != pd.as_deref()
        {
            return Err(issue(
                "ARC_AUTHORITY_NOT_ASSERTED",
                "current observed Codex Legion or Sage host event required",
            ));
        }
        prior = Some(r.clone())
    }
    if rs.is_empty() {
        return Err(issue(
            "ARC_AUTHORITY_NOT_ASSERTED",
            "current observed Codex Legion or Sage host event required",
        ));
    }
    let cur = rs
        .iter()
        .filter(|r| {
            r["adapter"] == adapter
                && r["sessionId"] == session
                && matches!(
                    r["eventType"].as_str(),
                    Some("SessionStart" | "SubagentStart")
                )
                && matches!(r["observedAuthority"].as_str(), Some("legion" | "sage"))
        })
        .last();
    if cur.and_then(|x| x.get("eventId")) != b.get("observedEventId") {
        return Err(issue(
            "ARC_AUTHORITY_NOT_ASSERTED",
            "current observed Codex Legion or Sage host event required",
        ));
    }
    Ok(())
}

fn seal_record(
    cwd: &Path,
    c: &Value,
    b: &Value,
    adapter: &str,
) -> Result<(Value, bool), CommandError> {
    let authority = b["authority"].as_str().unwrap_or_default();
    if !matches!(authority, "legion" | "sage") {
        return Err(issue("ARC_AUTHORITY_NOT_ASSERTED",format!("agent is observed as authority '{authority}'; only Legion or Sage may seal an execution contract")));
    }
    let r = json!({"schemaVersion":1,"kind":"arcane-contract-seal","contractId":c["contractId"],"version":c["version"],"sourceRevision":c["sourceRevision"],"contractDigest":canonical_digest(c).map_err(|e|CommandError::integrity(e.to_string()))?,"dispatchDigest":null,"sealedBy":{"authority":authority,"assertedBy":format!("{adapter}:{}",b["agentIdDigest"].as_str().unwrap_or_default()),"verificationMethod":"capability-signature","perMessage":true},"sealedAt":now(),"contract":c});
    let root = state_root(cwd).join("contract-seals");
    fs::create_dir_all(&root).map_err(super::io_error)?;
    let p = state_file(
        &root,
        "arcane.contract-seal.key.v1",
        &[
            c["contractId"].as_str().unwrap_or_default().into(),
            c["version"].as_u64().unwrap_or_default().to_string(),
        ],
    )
    .map_err(|e| CommandError::integrity(e.to_string()))?;
    match fs::OpenOptions::new().write(true).create_new(true).open(&p) {
        Ok(mut f) => {
            use std::io::Write;
            let bytes = [
                legion_contracts::canonical_json_bytes(&r)
                    .map_err(|e| CommandError::integrity(e.to_string()))?,
                vec![b'\n'],
            ]
            .concat();
            f.write_all(&bytes).map_err(super::io_error)?;
            f.sync_all().map_err(super::io_error)?;
            Ok((r, true))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let old = read_json(p.to_string_lossy().as_ref(), "seal")?;
            let same = [
                "contractId",
                "version",
                "sourceRevision",
                "contractDigest",
                "dispatchDigest",
            ]
            .iter()
            .all(|k| old.get(*k) == r.get(*k))
                && old["contract"] == r["contract"]
                && old["sealedBy"]["authority"] == r["sealedBy"]["authority"];
            if !same {
                return Err(issue(
                    "ARC_CONTRACT_VERSION_MISMATCH",
                    "contract seal conflicts with immutable version",
                ));
            }
            Ok((old, false))
        }
        Err(e) => Err(super::io_error(e)),
    }
}

fn latest_event(cwd: &Path, session: &str, authority: &str) -> Option<Value> {
    let root = state_root(cwd).join("host-events");
    let mut rows: Vec<Value> = Vec::new();
    for x in fs::read_dir(root).ok()?.flatten() {
        let n = x.file_name().to_string_lossy().into_owned();
        if n.len() == 21 && n.ends_with(".json") {
            if let Ok(v) = serde_json::from_slice(&fs::read(x.path()).ok()?) {
                rows.push(v)
            }
        }
    }
    rows.sort_by_key(|x| x["eventSequence"].as_u64().unwrap_or(0));
    rows.into_iter()
        .rev()
        .find(|x| x["sessionId"] == session && x["observedAuthority"] == authority)
}
fn verify_event(event: &Value, ring: &KeyRing) -> Result<(), CommandError> {
    let fields = [
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
    let result = legion_arcane::receipt_auth::verify_record(
        event,
        event.get("authentication"),
        ring,
        &fields,
        &Map::new(),
        None,
    )
    .map_err(|e| issue(e.code(), e.to_string()))?;
    if !result.allowed {
        return Err(issue(
            "ARC_AUTHORITY_NOT_ASSERTED",
            "current Legion or Sage host event required for contract amendment",
        ));
    }
    Ok(())
}
fn amendment_proof(
    cwd: &Path,
    ring: &KeyRing,
    key_id: &str,
    event: &Value,
    c: &Value,
    role: &str,
) -> Result<String, CommandError> {
    let ed = canonical_digest(event).map_err(|e| CommandError::integrity(e.to_string()))?;
    let cd = canonical_digest(c).map_err(|e| CommandError::integrity(e.to_string()))?;
    let task = c["tasks"]
        .as_array()
        .and_then(|x| x.first())
        .and_then(Value::as_str)
        .unwrap_or("");
    let ver = c["version"].as_u64().unwrap_or(2).saturating_sub(1);
    let inv=canonical_digest(&json!({"eventDigest":ed,"purpose":"budget-amendment","role":role,"binding":{"sessionId":event["sessionId"],"runId":event["runId"],"taskId":task,"contractId":c["contractId"],"contractVersion":ver,"contractDigest":event["contractDigest"]}})).map_err(|e|CommandError::integrity(e.to_string()))?;
    let derived = format!("{key_id}:authority-proof:{role}:budget-amendment");
    let domain = format!("arcane-authority-proof:v1:{role}:budget-amendment");
    let _ = ring
        .get(&derived)
        .map_err(|e| issue(e.code(), e.to_string()))?;
    let u = json!({"schemaVersion":1,"kind":"arcane-authority-invocation-proof","invocationId":inv,"eventDigest":ed,"eventSequence":event["eventSequence"],"purpose":"budget-amendment","role":role,"sessionId":event["sessionId"],"runId":event["runId"],"taskId":task,"contractId":c["contractId"],"contractVersion":ver,"contractDigest":event["contractDigest"],"sourceRevision":event["sourceRevision"],"turnCorrelationDigest":event["turnCorrelationDigest"],"stopOrdinal":event["stopOrdinal"],"domain":format!("arcane-authority-proof:{role}:budget-amendment"),"issuedAt":now(),"expiresAt":now(),"nonce":ed});
    let a = sign_record(
        &u,
        ring,
        &derived,
        &[
            "schemaVersion",
            "kind",
            "invocationId",
            "eventDigest",
            "eventSequence",
            "purpose",
            "role",
            "sessionId",
            "runId",
            "taskId",
            "contractId",
            "contractVersion",
            "contractDigest",
            "sourceRevision",
            "turnCorrelationDigest",
            "stopOrdinal",
            "domain",
            "issuedAt",
            "expiresAt",
            "nonce",
        ],
        Some(&domain),
    )
    .map_err(|e| issue(e.code(), e.to_string()))?;
    let mut p = u.clone();
    p["authentication"] = a;
    let root = state_root(cwd).join("authority-invocations").join("proofs");
    fs::create_dir_all(&root).map_err(super::io_error)?;
    let path = root.join(format!("{}.json", inv.trim_start_matches("sha256:")));
    if !path.exists() {
        fs::write(path, serde_json::to_vec(&p).map_err(super::io_error)?)
            .map_err(super::io_error)?
    }
    let transitions = state_root(cwd)
        .join("authority-invocations")
        .join("transitions");
    fs::create_dir_all(&transitions).map_err(super::io_error)?;
    let transition = transitions.join(format!("{}-issued.json", inv.trim_start_matches("sha256:")));
    if !transition.exists() {
        fs::write(transition, serde_json::to_vec(&json!({"state":"ISSUED","proofDigest":canonical_digest(&p).map_err(|e|CommandError::integrity(e.to_string()))?,"at":p["issuedAt"]})).map_err(super::io_error)?)
            .map_err(super::io_error)?;
    }
    Ok(canonical_digest(&p).map_err(|e| CommandError::integrity(e.to_string()))?)
}

pub fn run(args: CommonArgs) -> CommandResult {
    let av = args
        .args
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if av.first().map(String::as_str) != Some("seal") {
        return Err(CommandError::usage(format!(
            "contract requires a subcommand: seal (got {})",
            av.first().map(String::as_str).unwrap_or("<none>")
        )));
    }
    let tail = &av[1..];
    let file = option(tail, "--file")?.ok_or_else(|| {
        CommandError::usage("contract seal requires --file <executable-contract.json>")
    })?;
    let agent = option(tail, "--agent")?;
    let session=option(tail,"--session")?.or_else(||std::env::var("CODEX_THREAD_ID").ok()).or_else(||std::env::var("CLAUDE_CODE_SESSION_ID").ok()).or_else(||std::env::var("CLAUDE_SESSION_ID").ok()).or_else(||std::env::var("CODEX_SESSION_ID").ok()).filter(|s|!s.is_empty()).ok_or_else(||CommandError::usage("ARC_SESSION_UNKNOWN: no session id available (checked --session, then CODEX_THREAD_ID, CLAUDE_CODE_SESSION_ID, CLAUDE_SESSION_ID, CODEX_SESSION_ID) — never guessed"))?;
    let adapter = option(tail, "--adapter")?.unwrap_or_else(|| "claude-code".into());
    let c = read_json(&file, "file")?;
    if !c.is_object() {
        return Err(CommandError::usage("contract must be a JSON object"));
    }
    let req = c
        .get("evidenceRequirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !req.is_empty() {
        let p = option(tail, "--reachability")?.ok_or_else(|| {
            issue(
                "ARC_UNSOUND_SEAL",
                "contract seal requires --reachability <evidence-lifecycle.json>",
            )
        })?;
        let l = read_json(&p, "reachability")?;
        if req.iter().any(|value| !value.is_string()) {
            return Err(issue(
                "ARC_UNSOUND_SEAL",
                "evidence lifecycle must exactly cover contract evidence requirements",
            ));
        }
        let mut x = req
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut y = l
            .get("requirements")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.get("contractRequirement").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        x.sort();
        y.sort();
        if x != y
            || y.windows(2).any(|w| w[0] == w[1])
            || l["allowed"] == json!(false)
            || !reachability_allowed(&l)
        {
            return Err(issue(
                "ARC_UNSOUND_SEAL",
                "evidence lifecycle must exactly cover contract evidence requirements",
            ));
        }
    }
    let tb = option(tail, "--task-budgets")?;
    let companion = if let Some(p) = tb.as_deref() {
        let v = read_json(p, "task-budgets")?;
        let tasks = v
            .get("tasks")
            .and_then(Value::as_array)
            .ok_or_else(|| CommandError::usage("task budget companion must contain tasks"))?;
        let mut a = tasks
            .iter()
            .filter_map(|x| x.get("taskId").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut b = c
            .get("tasks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        a.sort();
        b.sort();
        if a != b || a.windows(2).any(|w| w[0] == w[1]) {
            return Err(issue(
                "ARC_BINDING_MISMATCH",
                "task budget companion must exactly cover contract tasks",
            ));
        }
        Some(tasks.clone())
    } else {
        None
    };
    let cwd = std::env::current_dir().map_err(super::io_error)?;
    let kd = option(tail, "--key-dir")?.or_else(|| std::env::var("ARCANE_KEY_DIR").ok());
    let ring = match kd {
        Some(p) => KeyRing::load_dir(Path::new(&p)),
        None => KeyRing::load_canonical(),
    }
    .map_err(|e| {
        issue(
            e.code(),
            "canonical host keyring unavailable — a seal cannot be minted without one",
        )
    })?;
    let b = binding(&cwd, &adapter, &session, agent.as_deref())?;
    verify_codex(&cwd, &ring, &adapter, &session, &b)?;
    let auth = b["authority"].as_str().unwrap_or_default();
    if !matches!(auth, "legion" | "sage") {
        return Err(issue("ARC_AUTHORITY_NOT_ASSERTED",format!("agent is observed as authority '{auth}'; only Legion or Sage may seal an execution contract")));
    }
    let er = executable_errors(&c);
    if let Some((code, _, m)) = er.first() {
        return Err(issue(
            if code.starts_with("EXEC_") {
                "ARC_CONTRACT_NOT_EXECUTABLE"
            } else {
                "ARC_SCHEMA_INVALID"
            },
            m.clone(),
        ));
    }
    let (r, created) = seal_record(&cwd, &c, &b, &adapter)?;
    let mut count = 0;
    if let Some(tasks) = companion {
        let bo = c.get("budget").and_then(Value::as_object).ok_or_else(|| {
            issue(
                "ARC_SCHEMA_INVALID",
                "contract budget is required when task budgets are sealed",
            )
        })?;
        for key in ["objectiveLineageId", "objectiveDigest", "legionBlastMapCapMs", "sagePlanningCapMs", "maxContractVersions"] {
            if !bo.contains_key(key) {
                return Err(issue("ARC_SCHEMA_INVALID", format!("invalid budget binding: missing {key}")));
            }
        }
        if !is_string(bo.get("objectiveLineageId"), 1)
            || !digest_shape(bo.get("objectiveDigest"))
            || bo.get("legionBlastMapCapMs").and_then(Value::as_u64).map_or(true, |v| v < 1)
            || bo.get("sagePlanningCapMs").and_then(Value::as_u64).map_or(true, |v| v < 1)
            || bo.get("maxContractVersions") != Some(&json!(2))
        {
            return Err(issue("ARC_SCHEMA_INVALID", "invalid budget binding"));
        }
        let cd = canonical_digest(&c).map_err(|e| CommandError::integrity(e.to_string()))?;
        let kid = ring
            .active_key_id()
            .map_err(|e| issue(e.code(), e.to_string()))?;
        let mut budget = json!({"schemaVersion":1,"kind":"arcane-budget-governance","contractId":c["contractId"],"version":c["version"],"contractDigest":cd,"objectiveLineageId":bo["objectiveLineageId"],"objectiveDigest":bo["objectiveDigest"],"legionBlastMapCapMs":bo["legionBlastMapCapMs"],"sagePlanningCapMs":bo["sagePlanningCapMs"],"maxContractVersions":bo["maxContractVersions"],"resumeEvidence":null});
        let mut budget_fields: &[&str] = BUDGET_BOUND_FIELDS.as_slice();
        if c["version"].as_u64() == Some(2) {
            let prior = BudgetGovernanceStore::new(
                state_root(&cwd).join("budget-governance"),
                ring.clone(),
            )
            .require(c["contractId"].as_str().unwrap_or_default(), 1)
            .map_err(|e| issue(e.code(), e.to_string()))?;
            let event = latest_event(&cwd, &session, auth).ok_or_else(|| {
                issue(
                    "ARC_AUTHORITY_NOT_ASSERTED",
                    "current Legion or Sage host event required for contract amendment",
                )
            })?;
            verify_event(&event, &ring)?;
            let pd = amendment_proof(&cwd, &ring, &kid, &event, &c, auth)?;
            let am = json!({"schemaVersion":1,"kind":"arcane-budget-amendment","priorContractDigest":prior["contractDigest"],"newContractDigest":cd,"priorLegionBlastMapCapMs":prior["legionBlastMapCapMs"],"newLegionBlastMapCapMs":budget["legionBlastMapCapMs"],"priorSagePlanningCapMs":prior["sagePlanningCapMs"],"newSagePlanningCapMs":budget["sagePlanningCapMs"],"scopeExpanded":false,"invocationProofDigest":pd,"observedAt":now()});
            let aa = sign_record(
                &am,
                &ring,
                &kid,
                &BUDGET_AMENDMENT_BOUND_FIELDS,
                Some("arcane-budget-amendment-v1"),
            )
            .map_err(|e| issue(e.code(), e.to_string()))?;
            let mut amendment = am;
            amendment["authentication"] = aa;
            budget["amendmentEvidence"] = amendment;
            budget["userScopeExpansionEvidence"] = Value::Null;
            budget_fields = AMENDED_BUDGET_BOUND_FIELDS.as_slice();
        }
        let aa = sign_record(
            &budget,
            &ring,
            &kid,
            budget_fields,
            Some("arcane-budget-governance-v1"),
        )
        .map_err(|e| issue(e.code(), e.to_string()))?;
        budget["authentication"] = aa;
        BudgetGovernanceStore::new(state_root(&cwd).join("budget-governance"), ring.clone())
            .seal(&budget)
            .map_err(|e| issue(e.code(), e.to_string()))?;
        let store =
            TaskBudgetSealStore::new(state_root(&cwd).join("task-budget-seals"), ring.clone());
        for s in tasks {
            let task = s["taskId"].as_str().unwrap_or_default();
            if s["ownScope"].as_array().map_or(true, |a| a.is_empty())
                || s["activeTimeCapMs"].as_u64().map_or(true, |v| v < 1)
                || s["progressDeadlineMs"].as_u64().map_or(true, |v| v < 1)
                || s["evidenceReferences"]
                    .as_array()
                    .map_or(true, |a| a.is_empty() || a.iter().any(|v| !is_string(Some(v), 1)))
                || s["ownScope"].as_array().map_or(true, |a| a.iter().any(|v| !v.is_string()))
            {
                return Err(issue(
                    "ARC_SCHEMA_INVALID",
                    "task budget requires ownScope, positive ceilings, & evidence references",
                ));
            }
            let t = json!({"taskId":task,"ownScope":s["ownScope"]});
            let mut q = json!({"schemaVersion":1,"kind":"arcane-task-budget-seal","contractId":c["contractId"],"contractVersion":c["version"],"contractDigest":cd,"taskId":task,"taskDigest":canonical_digest(&t).map_err(|e|CommandError::integrity(e.to_string()))?,"scopeDigest":canonical_digest(&t["ownScope"]).map_err(|e|CommandError::integrity(e.to_string()))?,"activeTimeCapMs":s["activeTimeCapMs"],"progressDeadlineMs":s["progressDeadlineMs"],"evidenceReferences":s["evidenceReferences"],"sealedBy":{"authority":auth,"assertedBy":format!("{adapter}:{}",b["agentIdDigest"].as_str().unwrap_or_default()),"verificationMethod":"capability-signature","perMessage":true},"sealedAt":now()});
            let aa = sign_record(
                &q,
                &ring,
                &kid,
                &[
                    "schemaVersion",
                    "kind",
                    "contractId",
                    "contractVersion",
                    "contractDigest",
                    "taskId",
                    "taskDigest",
                    "scopeDigest",
                    "activeTimeCapMs",
                    "progressDeadlineMs",
                    "evidenceReferences",
                    "sealedBy",
                    "sealedAt",
                ],
                Some("arcane-task-budget-seal-v1"),
            )
            .map_err(|e| issue(e.code(), e.to_string()))?;
            q["authentication"] = aa;
            store.seal(&q).map_err(|e| issue(e.code(), e.to_string()))?;
            count += 1
        }
    }
    Ok(
        json!({"kind":"legion-contract-seal","contractId":r["contractId"],"version":r["version"],"contractDigest":r["contractDigest"],"sourceRevision":r["sourceRevision"],"sealedBy":r["sealedBy"],"created":created,"taskBudgetsSealed":count}),
    )
}
