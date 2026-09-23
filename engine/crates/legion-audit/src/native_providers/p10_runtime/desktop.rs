//! Native port of the legacy JS desktop-runtime provider spec
//! (`src/providers/runtime/desktop/**/index.mjs` and
//! `src/providers/runtime/worker/index.mjs`).
//!
//! Every function here mirrors the corresponding JS export byte-for-byte in
//! behaviour: same gap ids, same denominators, same status derivation, same
//! output shape (as JSON). Inputs and outputs are `serde_json::Value` to
//! match the duck-typed JS objects faithfully without inventing a typed
//! schema the integrator has not settled yet.
//!
//! Membrane/Blueprint integration is out of scope for this product line and
//! was not present in any of the ported JS files (verified by inspection);
//! nothing was dropped on that account.

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn dedup_sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

/// `sha256:[a-f0-9]{64}` without pulling in the `regex` crate.
fn is_sha256_digest(value: &str) -> bool {
    match value.strip_prefix("sha256:") {
        Some(rest) => rest.len() == 64 && rest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        None => false,
    }
}

fn obj<'a>(v: &'a Value) -> Option<&'a Map<String, Value>> {
    v.as_object()
}

fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    obj(v).and_then(|m| m.get(key)).unwrap_or(&NULL)
}

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    get(v, key).as_str()
}

fn get_str_or<'a>(v: &'a Value, key: &str, default: &'a str) -> &'a str {
    get_str(v, key).unwrap_or(default)
}

fn get_bool(v: &Value, key: &str) -> Option<bool> {
    get(v, key).as_bool()
}

fn get_true(v: &Value, key: &str) -> bool {
    get_bool(v, key) == Some(true)
}

fn get_f64(v: &Value, key: &str) -> Option<f64> {
    get(v, key).as_f64()
}

fn get_array<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    get(v, key).as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn id_of(v: &Value) -> String {
    get_str_or(v, "id", "unknown").to_string()
}

fn is_present_str(v: &Value) -> bool {
    matches!(v, Value::String(s) if !s.is_empty())
}

/// JS truthiness for a JSON value: `null`/`false`/`0`/`""` are falsy,
/// everything else (including empty arrays/objects) is truthy.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_none_or(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn falsy(v: &Value) -> bool {
    !truthy(v)
}

/// `[...new Set(v)]`: de-duplicate while preserving first-occurrence order.
fn dedup_preserve_order(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|item| seen.insert(item.clone())).collect()
}

/// A very small case-insensitive substring search over ASCII text; mirrors
/// what the JS `RegExp` `i` flag needs for the patterns this file ports.
fn find_ci(haystack: &[u8], needle: &str) -> Option<usize> {
    let needle_lower = needle.to_ascii_lowercase();
    let needle = needle_lower.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    for start in 0..=haystack.len() - needle.len() {
        if haystack[start..start + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
        {
            return Some(start);
        }
    }
    None
}

/// Faithful (manual) port of
/// `/(bearer\s+\S+|https?:\/\/\S+[?&](?:token|signature|sig)=)/i`.
/// `String(value)` coercion: use the raw text for a JSON string, otherwise
/// its JSON representation (close enough for the log lines this checks).
fn js_string_coerce(v: &Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())
}

fn looks_sensitive(value: &str) -> bool {
    let bytes = value.as_bytes();

    // `bearer\s+\S+`
    let mut search_from = 0usize;
    while let Some(rel) = find_ci(&bytes[search_from..], "bearer") {
        let mut i = search_from + rel + "bearer".len();
        let mut saw_space = false;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            saw_space = true;
            i += 1;
        }
        if saw_space && i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            return true;
        }
        search_from = search_from + rel + "bearer".len();
        if search_from >= bytes.len() {
            break;
        }
    }

    // `https?:\/\/\S+[?&](?:token|signature|sig)=`
    for scheme in ["https://", "http://"] {
        let mut search_from = 0usize;
        while let Some(rel) = find_ci(&bytes[search_from..], scheme) {
            let start = search_from + rel + scheme.len();
            let mut end = start;
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            let run = &value[start..end];
            for marker in ["?token=", "&token=", "?signature=", "&signature=", "?sig=", "&sig="] {
                if find_ci(run.as_bytes(), marker).is_some() {
                    return true;
                }
            }
            search_from = start;
            if search_from >= bytes.len() {
                break;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------
// files/index.mjs
// ---------------------------------------------------------------------

const TERMINAL_STATUSES: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];

pub const FILE_CASES: &[&str] = &[
    "empty", "zero-byte", "large", "malformed", "unsupported", "duplicate", "read-only", "network",
    "cloud-synced", "externally-changed", "externally-deleted", "long-path", "unicode-rtl", "symlink",
    "archive-bomb", "permission-boundary", "atomic-save", "cancellation", "disk-full", "temp-cleanup",
    "corruption", "backup-restore", "os-user-isolation", "cloud-conflict", "deep-link", "clipboard",
    "drag-drop", "open-save-dialog", "file-association",
];

pub fn evaluate_desktop_storage(input: &Value) -> Value {
    let cases: Vec<Value> = get_array(input, "cases").to_vec();
    let migrations: Vec<Value> = get_array(input, "migrations").to_vec();
    let locations = get(input, "locations").clone();
    let locations = if locations.is_null() { json!({}) } else { locations };
    let evidence = get(input, "evidence").clone();
    let evidence = if evidence.is_null() { json!({}) } else { evidence };

    let receipts: Vec<Value> = cases.iter().cloned().chain(migrations.iter().cloned()).collect();
    let mut gaps: Vec<String> = Vec::new();

    for item in &receipts {
        let has_id = is_present_str(get(item, "id"));
        let terminal = get_true(item, "terminal");
        let status_ok = get_str(item, "status").is_some_and(|s| TERMINAL_STATUSES.contains(&s));
        if !has_id || !terminal || !status_ok {
            gaps.push(format!("scenario-unproven:{}", id_of(item)));
        }
    }
    for migration in &migrations {
        if get_str(migration, "status") != Some("pass") && !get_true(migration, "sourcePreserved") {
            gaps.push(format!("migration-source-not-preserved:{}", id_of(migration)));
        }
    }

    let location_values: Vec<&Value> = ["data", "cache", "logs", "temp"]
        .iter()
        .map(|key| get(&locations, key))
        .filter(|v| truthy(v))
        .collect();
    if location_values.len() != 4 {
        gaps.push("storage-locations-incomplete".to_string());
    } else {
        let mut unique: Vec<String> = location_values.iter().map(|v| v.to_string()).collect();
        unique.sort();
        unique.dedup();
        if unique.len() != 4 {
            gaps.push("storage-locations-not-separated".to_string());
        }
    }

    for id in FILE_CASES {
        if !cases
            .iter()
            .any(|item| get_str(item, "id") == Some(*id) && get_true(item, "terminal"))
        {
            gaps.push(format!("file-case-missing:{id}"));
        }
    }
    if migrations.is_empty() {
        gaps.push("migration-denominator-empty".to_string());
    }
    if get_str(&evidence, "source") != Some("native-host") || !get_true(&evidence, "terminal") {
        gaps.push("native-storage-receipt-missing".to_string());
    }

    let status = if gaps.iter().any(|g| g.starts_with("migration-source-not-preserved")) {
        "fail"
    } else if !gaps.is_empty() {
        "unproven"
    } else {
        "pass"
    };

    let accounted = receipts
        .iter()
        .filter(|item| {
            is_present_str(get(item, "id"))
                && get_true(item, "terminal")
                && get_str(item, "status").is_some_and(|s| TERMINAL_STATUSES.contains(&s))
        })
        .count();

    json!({
        "schemaVersion": 1,
        "kind": "legion-desktop-files-storage",
        "status": status,
        "terminal": true,
        "locations": locations,
        "receipts": receipts,
        "evidence": evidence,
        "denominator": { "total": receipts.len(), "accounted": accounted },
        "coverageGaps": sorted(gaps),
    })
}

/// Host contract for `executeDesktopStorage`. All methods are sync in this
/// port; callers running an async native host adapt at the call site.
pub trait FilesHost {
    fn run(&self, request: &Value) -> Value;
    fn locations(&self) -> Value;
    fn receipt(&self) -> Option<Value> {
        None
    }
}

pub fn execute_desktop_storage(host: Option<&dyn FilesHost>, migration_ids: &[String]) -> Value {
    let Some(host) = host else {
        return evaluate_desktop_storage(&json!({}));
    };
    let cases: Vec<Value> = FILE_CASES
        .iter()
        .map(|id| host.run(&json!({ "id": id, "kind": "file-storage" })))
        .collect();
    let migrations: Vec<Value> = migration_ids
        .iter()
        .map(|id| host.run(&json!({ "id": id, "kind": "migration" })))
        .collect();
    let evidence = host.receipt().unwrap_or_else(|| json!({}));
    evaluate_desktop_storage(&json!({
        "cases": cases,
        "migrations": migrations,
        "locations": host.locations(),
        "evidence": evidence,
    }))
}

// ---------------------------------------------------------------------
// desktop/index.mjs
// ---------------------------------------------------------------------

pub const REQUIRED_EVIDENCE_FAMILIES: &[&str] = &[
    "process", "ipc", "files", "storage", "os", "performance", "installer", "updater", "platform",
];

struct Account {
    total: usize,
    accounted: usize,
    missing: Vec<String>,
}

fn account_json(a: &Account) -> Value {
    json!({ "total": a.total, "accounted": a.accounted, "missing": a.missing })
}

fn account(expected: &[String], actual: &[String]) -> Account {
    let mut ids: Vec<String> = expected.to_vec();
    ids.sort();
    ids.dedup();
    let present: std::collections::HashSet<&String> = actual.iter().collect();
    let missing: Vec<String> = ids.iter().filter(|id| !present.contains(id)).cloned().collect();
    Account { total: ids.len(), accounted: ids.len() - missing.len(), missing }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    find_ci(haystack.as_bytes(), needle).is_some()
}

fn families_for(receipt: &Value) -> Vec<String> {
    if let Some(arr) = get(receipt, "evidenceFamilies").as_array() {
        return arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    }
    if let Some(family) = get_str(receipt, "evidenceFamily") {
        return vec![family.to_string()];
    }
    match get_str(receipt, "kind") {
        Some("legion-desktop-runtime") => vec!["process".to_string()],
        Some("legion-desktop-ipc") => vec!["ipc".to_string()],
        Some("legion-desktop-files-storage") => vec!["files".to_string(), "storage".to_string()],
        Some("legion-desktop-os-matrix") => vec!["os".to_string()],
        Some("legion-desktop-performance") => vec!["performance".to_string()],
        Some("legion-desktop-installer-lifecycle") => vec!["installer".to_string()],
        Some("legion-desktop-updater") => vec!["updater".to_string()],
        Some("legion-desktop-windows") | Some("legion-desktop-macos") | Some("legion-desktop-linux") => {
            vec!["platform".to_string()]
        }
        _ => vec![],
    }
}

pub fn integrate_desktop_evidence(input: &Value) -> Value {
    let target_id = get(input, "targetId").clone();
    let controls: Vec<String> = get_array(input, "controls").iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let scenarios: Vec<String> = get_array(input, "scenarios").iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let receipts_in: Vec<Value> = get_array(input, "receipts").to_vec();
    let platform_matrices: Vec<Value> = get_array(input, "platformMatrices").to_vec();

    let mut gaps: Vec<String> = Vec::new();
    let mut admitted: Vec<Value> = Vec::new();

    for receipt in &receipts_in {
        let receipt_control_or_scenario = get_str(receipt, "controlId")
            .or_else(|| get_str(receipt, "scenarioId"))
            .unwrap_or("unknown");
        if get(receipt, "targetId") != &target_id {
            gaps.push(format!("target-binding-mismatch:{receipt_control_or_scenario}"));
            continue;
        }
        if !get_true(receipt, "terminal") {
            gaps.push(format!("receipt-nonterminal:{receipt_control_or_scenario}"));
            continue;
        }
        let control_id = get_str(receipt, "controlId").unwrap_or("");
        let source_regex_only = get_true(receipt, "sourceRegexOnly")
            || (get_str(receipt, "claimLevel") == Some("source") && contains_ci(control_id, "release"));
        if source_regex_only {
            gaps.push(format!("native-release-evidence-missing:{control_id}"));
        }
        admitted.push(receipt.clone());
    }

    let closure_receipts: Vec<&Value> = admitted
        .iter()
        .filter(|item| {
            let control_id = get_str(item, "controlId").unwrap_or("");
            !(get_true(item, "sourceRegexOnly")
                || (get_str(item, "claimLevel") == Some("source") && contains_ci(control_id, "release")))
        })
        .collect();

    let control_ids: Vec<String> = closure_receipts.iter().filter_map(|item| get_str(item, "controlId").map(str::to_string)).collect();
    let scenario_ids: Vec<String> = closure_receipts.iter().filter_map(|item| get_str(item, "scenarioId").map(str::to_string)).collect();
    let control_counts = account(&controls, &control_ids);
    let scenario_counts = account(&scenarios, &scenario_ids);

    let mut present_families: Vec<String> = admitted.iter().flat_map(families_for).collect();
    present_families.sort();
    present_families.dedup();
    let required_families: Vec<String> = REQUIRED_EVIDENCE_FAMILIES.iter().map(|s| s.to_string()).collect();
    let evidence_families = account(&required_families, &present_families);

    gaps.extend(control_counts.missing.iter().map(|id| format!("control-missing:{id}")));
    gaps.extend(scenario_counts.missing.iter().map(|id| format!("scenario-missing:{id}")));
    gaps.extend(evidence_families.missing.iter().map(|id| format!("evidence-family-missing:{id}")));

    for matrix in &platform_matrices {
        let os = get_str(matrix, "os");
        let status = get_str(matrix, "status");
        let status_ok = status.is_some_and(|s| ["pass", "unsupported", "unproven", "partial", "fail"].contains(&s));
        if os.is_none() || !status_ok {
            gaps.push(format!("platform-matrix-invalid:{}", os.unwrap_or("unknown")));
        }
    }

    let stop_ship = gaps.iter().any(|g| {
        contains_ci(g, "nonterminal") || contains_ci(g, "binding-mismatch") || contains_ci(g, "native-release")
    }) || admitted.iter().any(|item| {
        matches!(get_str(item, "status"), Some("fail") | Some("error") | Some("blocked"))
    });

    let status = if stop_ship {
        "fail"
    } else if !gaps.is_empty() {
        "partial"
    } else {
        "pass"
    };

    json!({
        "schemaVersion": 1,
        "kind": "legion-desktop-platform-pack",
        "status": status,
        "terminal": true,
        "provisional": true,
        "stopShip": stop_ship,
        "incomplete": !gaps.is_empty(),
        "targetId": target_id,
        "denominator": {
            "controls": account_json(&control_counts),
            "scenarios": account_json(&scenario_counts),
            "evidenceFamilies": account_json(&evidence_families),
        },
        "receipts": admitted,
        "platformMatrices": platform_matrices,
        "coverageGaps": dedup_sorted(gaps),
    })
}

// ---------------------------------------------------------------------
// installer/index.mjs
// ---------------------------------------------------------------------

pub const INSTALLER_CASES: &[&str] = &[
    "install", "repair", "upgrade", "downgrade", "rollback", "uninstall", "reinstall",
    "interrupted-install", "offline-uninstall", "locked-files", "modes", "snapshots", "logs", "changes",
    "cleanup",
];
const NEGATIVE_INSTALLER_CASES: &[&str] = &["interrupted-install", "offline-uninstall", "locked-files"];
const SIGNATURE_RECEIPT_REQUIRED: bool = true;

/// Matches the JS `throw new Error(...)` for an unsafe destructive target.
pub fn evaluate_installer_lifecycle(input: &Value) -> Result<Value, String> {
    let destructive_target = get(input, "destructiveTarget");
    if !destructive_target.is_null() {
        let raw = match destructive_target {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let normalized = raw.replace('\\', "/").to_lowercase();
        let has_temp_segment = normalized.split('/').any(|seg| seg == "temp") || normalized == "temp";
        if !has_temp_segment {
            return Err("destructive installer scenarios require an isolated temp target".to_string());
        }
    }

    let pkg = get(input, "package").clone();
    let pkg = if pkg.is_null() { json!({}) } else { pkg };
    let capability = get(input, "capability").clone();
    let capability = if capability.is_null() { json!({}) } else { capability };
    let scenarios: Vec<Value> = get_array(input, "scenarios").to_vec();

    let mut gaps: Vec<String> = Vec::new();
    let digest_ok = get_str(&pkg, "digest").is_some_and(is_sha256_digest);
    if !digest_ok || !get_true(&pkg, "production") {
        gaps.push("production-package-unproven".to_string());
    }
    if SIGNATURE_RECEIPT_REQUIRED {
        let sig = get(&pkg, "signatureReceipt");
        let sig_ok = get_str(sig, "status") == Some("pass") && get_str(sig, "artifactDigest") == get_str(&pkg, "digest");
        if !sig_ok {
            gaps.push("signature-receipt-unproven".to_string());
        }
    }
    if get_str(&capability, "status") != Some("available") {
        let reason = get_str(&capability, "reason").or_else(|| get_str(&capability, "status")).unwrap_or("missing");
        gaps.push(format!("installer-capability-{reason}"));
    }
    for scenario in &scenarios {
        let sid = get_str(scenario, "id").unwrap_or("");
        if !get_true(scenario, "terminal") {
            gaps.push(format!("scenario-nonterminal:{}", id_of(scenario)));
        }
        if sid == "rollback" && !get_true(scenario, "newerDataPreserved") {
            gaps.push("rollback-newer-data-unsafe".to_string());
        }
        if NEGATIVE_INSTALLER_CASES.contains(&sid) && get_str(scenario, "status") != Some("fail") {
            gaps.push(format!("negative-case-not-failed:{sid}"));
        }
        if sid == "modes" && get_array(scenario, "modes").is_empty() {
            gaps.push("modes-not-documented".to_string());
        }
        if sid == "snapshots" && falsy(get(scenario, "snapshotCount")) {
            gaps.push("snapshots-not-documented".to_string());
        }
        if sid == "logs" && falsy(get(scenario, "logFile")) {
            gaps.push("logs-not-documented".to_string());
        }
        if sid == "changes" && get_array(scenario, "changes").is_empty() {
            gaps.push("changes-not-documented".to_string());
        }
        if sid == "cleanup" && truthy(get(scenario, "artifactsRemaining")) {
            gaps.push("cleanup-not-complete".to_string());
        }
    }
    for id in INSTALLER_CASES {
        if !scenarios.iter().any(|s| get_str(s, "id") == Some(*id) && get_true(s, "terminal")) {
            gaps.push(format!("lifecycle-case-missing:{id}"));
        }
    }
    let unsafe_rollback = gaps.iter().any(|g| g == "rollback-newer-data-unsafe");
    let status = if unsafe_rollback {
        "fail"
    } else if !gaps.is_empty() {
        "partial"
    } else {
        "pass"
    };
    let accounted = scenarios.iter().filter(|s| get_true(s, "terminal")).count();
    let negative_cases = scenarios
        .iter()
        .filter(|s| {
            let sid = get_str(s, "id").unwrap_or("");
            NEGATIVE_INSTALLER_CASES.contains(&sid) && get_str(s, "status") == Some("fail")
        })
        .count();

    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-desktop-installer-lifecycle",
        "status": status,
        "terminal": true,
        "package": pkg,
        "capability": capability,
        "scenarios": scenarios,
        "releaseClaim": gaps.is_empty(),
        "denominator": {
            "total": INSTALLER_CASES.len(),
            "required": INSTALLER_CASES.len(),
            "accounted": accounted,
            "negativeCases": negative_cases,
        },
        "coverageGaps": sorted(gaps),
    }))
}

pub trait InstallerHost {
    fn run(&self, request: &Value) -> Value;
}

pub fn execute_installer_lifecycle(
    host: Option<&dyn InstallerHost>,
    package: &Value,
    capability: &Value,
    destructive_target: &Value,
) -> Result<Value, String> {
    let Some(host) = host else {
        return evaluate_installer_lifecycle(&json!({
            "package": package, "capability": capability, "destructiveTarget": destructive_target,
        }));
    };
    let scenarios: Vec<Value> = INSTALLER_CASES
        .iter()
        .map(|id| host.run(&json!({ "id": id, "package": package, "destructiveTarget": destructive_target, "isolated": true })))
        .collect();
    evaluate_installer_lifecycle(&json!({
        "package": package, "capability": capability, "scenarios": scenarios, "destructiveTarget": destructive_target,
    }))
}

// ---------------------------------------------------------------------
// ipc/index.mjs
// ---------------------------------------------------------------------

pub const IPC_CASES: &[&str] = &["allowed", "denied", "malformed", "oversized", "replayed", "wrong-caller", "stale-session", "shutdown"];
const IPC_INVENTORY: &[&str] = &["sockets", "plugins", "sidecars"];
const IPC_BOUNDARIES: &[&str] = &["navigation", "remoteContent", "externalUrl", "shell", "process", "filesystem"];

fn is_denied_case(id: &str) -> bool {
    IPC_CASES.contains(&id) && id != "allowed"
}

fn str_array_contains(arr: &[Value], needle: &Value) -> bool {
    arr.iter().any(|v| v == needle)
}

pub fn evaluate_desktop_ipc(input: &Value) -> Value {
    let commands: Vec<Value> = get_array(input, "commands").to_vec();
    let attempts: Vec<Value> = get_array(input, "attempts").to_vec();
    let helpers: Vec<Value> = get_array(input, "helpers").to_vec();
    let inventory = get(input, "inventory").clone();
    let inventory = if inventory.is_null() { json!({}) } else { inventory };
    let boundaries = get(input, "boundaries").clone();
    let boundaries = if boundaries.is_null() { json!({}) } else { boundaries };
    let evidence = get(input, "evidence").clone();
    let evidence = if evidence.is_null() { json!({}) } else { evidence };

    let find_command = |command_id: &Value| commands.iter().find(|c| get(c, "id") == command_id);

    let receipts: Vec<Value> = attempts
        .iter()
        .map(|attempt| {
            let attempt_id = get_str_or(attempt, "id", "unknown").to_string();
            let command = find_command(get(attempt, "command"));
            let Some(command) = command else {
                return json!({ "id": attempt_id, "status": "blocked", "terminal": true, "reason": "unknown-command" });
            };
            let actors = get_array(command, "actors");
            if !str_array_contains(actors, get(attempt, "actor")) {
                return json!({ "id": attempt_id, "status": "blocked", "terminal": true, "reason": "caller-denied" });
            }
            let capabilities = get_array(command, "capabilities");
            let attempt_capabilities = get_array(attempt, "capabilities");
            let has_all = capabilities.iter().all(|item| str_array_contains(attempt_capabilities, item));
            if !has_all {
                return json!({ "id": attempt_id, "status": "blocked", "terminal": true, "reason": "capability-denied" });
            }
            if is_denied_case(&attempt_id) && !get_true(attempt, "observedDenied") {
                return json!({ "id": attempt_id, "status": "fail", "terminal": true, "reason": "denial-bypassed" });
            }
            json!({ "id": attempt_id, "status": "pass", "terminal": true })
        })
        .collect();

    let mut gaps: Vec<String> = Vec::new();
    for helper in &helpers {
        let hid = id_of(helper);
        if !get_str(helper, "digest").is_some_and(is_sha256_digest) {
            gaps.push(format!("helper-identity-unproven:{hid}"));
        }
        if !get_true(helper, "stopped") {
            gaps.push(format!("helper-outlived-parent:{hid}"));
        }
        if !get_array(helper, "inheritedHandles").is_empty() {
            gaps.push(format!("helper-handles-inherited:{hid}"));
        }
        if falsy(get(helper, "workingDirectory")) || !get_true(helper, "environmentBound") {
            gaps.push(format!("helper-context-unproven:{hid}"));
        }
    }
    for command in &commands {
        let cid = id_of(command);
        if get(command, "schema").is_null()
            || get(command, "arguments").is_null()
            || get(command, "privilege").is_null()
            || get(command, "identity").is_null()
        {
            gaps.push(format!("command-contract-incomplete:{cid}"));
        }
    }
    for id in IPC_CASES {
        if !attempts.iter().any(|a| get_str(a, "id") == Some(*id) && get_true(a, "terminal")) {
            gaps.push(format!("ipc-case-missing:{id}"));
        }
    }
    for key in IPC_INVENTORY {
        if get(&inventory, key).as_array().is_none() {
            gaps.push(format!("inventory-missing:{key}"));
        }
    }
    for key in IPC_BOUNDARIES {
        if !get_true(&boundaries, key) {
            gaps.push(format!("boundary-unproven:{key}"));
        }
    }
    if get_str(&evidence, "source") != Some("native-host") || !get_true(&evidence, "terminal") {
        gaps.push("native-ipc-receipt-missing".to_string());
    }

    let commands_out: Vec<Value> = commands
        .iter()
        .map(|c| json!({ "id": get(c, "id"), "actors": get_array(c, "actors"), "capabilities": get_array(c, "capabilities") }))
        .collect();

    json!({
        "schemaVersion": 1,
        "kind": "legion-desktop-ipc",
        "status": if gaps.is_empty() { "pass" } else { "unproven" },
        "terminal": true,
        "commands": commands_out,
        "receipts": receipts,
        "helpers": helpers,
        "inventory": inventory,
        "boundaries": boundaries,
        "evidence": evidence,
        "coverageGaps": dedup_sorted(gaps),
    })
}

pub trait IpcHost {
    fn exercise(&self, request: &Value) -> Value;
    fn receipt(&self) -> Option<Value> {
        None
    }
}

pub fn execute_desktop_ipc(host: Option<&dyn IpcHost>, commands: &Value, helpers: &Value, inventory: &Value, boundaries: &Value) -> Value {
    let Some(host) = host else {
        return evaluate_desktop_ipc(&json!({ "commands": commands, "helpers": helpers, "inventory": inventory, "boundaries": boundaries }));
    };
    let attempts: Vec<Value> = IPC_CASES
        .iter()
        .map(|case_id| host.exercise(&json!({ "caseId": case_id, "commands": commands, "inventory": inventory, "boundaries": boundaries })))
        .collect();
    let evidence = host.receipt().unwrap_or_else(|| json!({}));
    evaluate_desktop_ipc(&json!({
        "commands": commands, "attempts": attempts, "helpers": helpers, "inventory": inventory, "boundaries": boundaries, "evidence": evidence,
    }))
}

// ---------------------------------------------------------------------
// linux/index.mjs & macos/index.mjs (shared shape)
// ---------------------------------------------------------------------

pub const LINUX_CASES: &[&str] = &[
    "xdg", "x11-wayland", "libraries", "appimage", "flatpak", "snap", "deb-rpm", "desktop-entry",
    "mime-protocol", "polkit", "sandbox", "distribution-desktop",
];

pub const MACOS_CASES: &[&str] = &[
    "hardened-runtime", "notarization", "gatekeeper", "entitlements", "app-sandbox", "keychain", "tcc",
    "app-translocation", "architectures", "login-items-helpers", "menus-windows", "residual-data",
];

fn bound_matrix(os: &str, matrix: &Value) -> Value {
    json!({ "os": os, "version": get(matrix, "version"), "architecture": get(matrix, "architecture") })
}

pub fn evaluate_linux_platform(input: &Value) -> Value {
    let matrix = get(input, "matrix").clone();
    let artifact = get(input, "artifact").clone();
    let artifact = if artifact.is_null() { json!({}) } else { artifact };
    let checks: Vec<Value> = get_array(input, "checks").to_vec();
    let capability = get(input, "capability").clone();
    let capability = if capability.is_null() { json!({}) } else { capability };

    let bound = bound_matrix("linux", &matrix);
    let mut gaps: Vec<String> = Vec::new();
    if falsy(get(&bound, "version")) || falsy(get(&bound, "architecture")) {
        gaps.push("linux-matrix-incomplete".to_string());
    }
    let capability_available = get_str(&capability, "status") == Some("available");
    if !capability_available {
        let reason = get_str(&capability, "reason").or_else(|| get_str(&capability, "status")).unwrap_or("missing");
        gaps.push(format!("linux-capability-unavailable:{reason}"));
    }
    for check in &checks {
        if !get_true(check, "terminal") {
            gaps.push(format!("linux-check-nonterminal:{}", id_of(check)));
        }
    }
    if capability_available {
        for id in LINUX_CASES {
            if !checks.iter().any(|c| get_str(c, "id") == Some(*id) && get_true(c, "terminal")) {
                gaps.push(format!("linux-case-missing:{id}"));
            }
        }
    }
    json!({
        "schemaVersion": 1, "kind": "legion-desktop-linux",
        "status": if gaps.is_empty() { "pass" } else { "unproven" }, "terminal": true,
        "matrix": bound, "artifact": artifact, "receipts": checks, "coverageGaps": sorted(gaps),
    })
}

pub fn evaluate_macos_platform(input: &Value) -> Value {
    let matrix = get(input, "matrix").clone();
    let artifact = get(input, "artifact").clone();
    let artifact = if artifact.is_null() { json!({}) } else { artifact };
    let checks: Vec<Value> = get_array(input, "checks").to_vec();
    let capability = get(input, "capability").clone();
    let capability = if capability.is_null() { json!({}) } else { capability };

    let bound = bound_matrix("macos", &matrix);
    let mut gaps: Vec<String> = Vec::new();
    if falsy(get(&bound, "version")) || falsy(get(&bound, "architecture")) {
        gaps.push("macos-matrix-incomplete".to_string());
    }
    let capability_available = get_str(&capability, "status") == Some("available");
    if !capability_available {
        let reason = get_str(&capability, "reason").or_else(|| get_str(&capability, "status")).unwrap_or("missing");
        gaps.push(format!("macos-capability-unavailable:{reason}"));
    }
    for check in &checks {
        let cid = id_of(check);
        if !get_true(check, "terminal") {
            gaps.push(format!("macos-check-nonterminal:{cid}"));
        }
        if (cid == "notarization" || cid == "gatekeeper")
            && (!get_true(&artifact, "final") || get(check, "artifactDigest") != get(&artifact, "digest"))
        {
            gaps.push(format!("macos-final-artifact-unproven:{cid}"));
        }
    }
    if capability_available {
        for id in MACOS_CASES {
            if !checks.iter().any(|c| get_str(c, "id") == Some(*id) && get_true(c, "terminal")) {
                gaps.push(format!("macos-case-missing:{id}"));
            }
        }
    }
    json!({
        "schemaVersion": 1, "kind": "legion-desktop-macos",
        "status": if gaps.is_empty() { "pass" } else { "unproven" }, "terminal": true,
        "matrix": bound, "artifact": artifact, "receipts": checks, "coverageGaps": sorted(gaps),
    })
}

pub trait PlatformCheckHost {
    fn check(&self, request: &Value) -> Value;
}

pub fn execute_linux_platform(host: Option<&dyn PlatformCheckHost>, input: &Value) -> Value {
    let Some(host) = host else { return evaluate_linux_platform(input) };
    let artifact = get(input, "artifact");
    let checks: Vec<Value> = LINUX_CASES.iter().map(|id| host.check(&json!({ "os": "linux", "id": id, "artifact": artifact }))).collect();
    let mut merged = input.clone();
    merged["checks"] = json!(checks);
    evaluate_linux_platform(&merged)
}

pub fn execute_macos_platform(host: Option<&dyn PlatformCheckHost>, input: &Value) -> Value {
    let Some(host) = host else { return evaluate_macos_platform(input) };
    let artifact = get(input, "artifact");
    let checks: Vec<Value> = MACOS_CASES.iter().map(|id| host.check(&json!({ "os": "macos", "id": id, "artifact": artifact }))).collect();
    let mut merged = input.clone();
    merged["checks"] = json!(checks);
    evaluate_macos_platform(&merged)
}

// ---------------------------------------------------------------------
// os-integration/index.mjs
// ---------------------------------------------------------------------

const OS_ALLOWED_STATUSES: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error", "unsupported"];
const HOST_UNAVAILABLE_TYPES: &[&str] = &["remote-host", "device-not-present", "os-version-unavailable", "license-restricted"];

pub const DESKTOP_OS_CASES: &[&str] = &[
    "single-instance", "multi-window", "focus-modal", "tray-menu", "autostart", "notifications", "shortcuts",
    "exit", "window-restore", "missing-monitor", "mixed-dpi", "display-hotplug", "high-contrast",
    "reduced-motion", "ime", "non-us-keyboard", "screen-reader", "keyboard-only", "installer-keyboard",
    "updater-screen-reader", "sleep-resume", "permission-revocation", "non-admin",
];

pub fn compile_desktop_os_matrix(input: &Value) -> Value {
    let required: Vec<String> = match get(input, "required").as_array() {
        Some(arr) => arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        None if get(input, "required").is_null() => DESKTOP_OS_CASES.iter().map(|s| s.to_string()).collect(),
        None => vec![],
    };
    let requested = dedup_preserve_order(required);
    let supplied: Vec<Value> = get(input, "cases").as_array().cloned().unwrap_or_default();

    let find = |id: &str| supplied.iter().find(|item| get_str(item, "id") == Some(id));
    let receipts: Vec<Value> = requested
        .iter()
        .map(|id| match find(id) {
            Some(v) => v.clone(),
            None => json!({ "id": id, "status": "unproven", "terminal": true, "synthesized": true }),
        })
        .collect();

    let mut gaps: Vec<String> = Vec::new();
    for item in &supplied {
        let iid = get_str(item, "id").unwrap_or("");
        if !requested.iter().any(|r| r == iid) {
            gaps.push(format!("caller-defined-matrix-case:{iid}"));
        }
    }
    if requested.is_empty() {
        gaps.push("matrix-denominator-empty".to_string());
    }
    for item in &receipts {
        let iid = id_of(item);
        let status = get_str(item, "status");
        if !get_true(item, "terminal") || !status.is_some_and(|s| OS_ALLOWED_STATUSES.contains(&s)) {
            gaps.push(format!("terminal-status-invalid:{iid}"));
        }
        if falsy(get(item, "os")) || falsy(get(item, "version")) || falsy(get(item, "architecture")) {
            gaps.push(format!("platform-binding-incomplete:{iid}"));
        }
        if !get(item, "state").is_object() {
            gaps.push(format!("native-state-missing:{iid}"));
        }
        if get_array(item, "controlIds").is_empty() {
            gaps.push(format!("control-binding-missing:{iid}"));
        }
        if status == Some("unsupported") {
            if falsy(get(item, "reason")) {
                gaps.push(format!("unsupported-reason-missing:{iid}"));
            }
            let host_unavailable = get(item, "hostUnavailable");
            if !host_unavailable.is_object() {
                gaps.push(format!("host-unavailable-evidence-missing:{iid}"));
            } else if !get_str(host_unavailable, "type").is_some_and(|t| HOST_UNAVAILABLE_TYPES.contains(&t)) {
                gaps.push(format!("host-unavailable-type-invalid:{iid}"));
            } else if falsy(get(host_unavailable, "detail")) {
                gaps.push(format!("host-unavailable-detail-missing:{iid}"));
            }
        }
        if get_true(item, "synthesized") {
            gaps.push(format!("matrix-case-missing:{iid}"));
        }
    }

    let accounted = receipts
        .iter()
        .filter(|item| {
            !get_true(item, "synthesized")
                && get_true(item, "terminal")
                && get_str(item, "status").is_some_and(|s| OS_ALLOWED_STATUSES.contains(&s))
        })
        .count();
    let synthesized = receipts.iter().filter(|item| get_true(item, "synthesized")).count();

    json!({
        "schemaVersion": 1, "kind": "legion-desktop-os-matrix",
        "status": if gaps.is_empty() { "pass" } else { "unproven" }, "terminal": true,
        "receipts": receipts,
        "denominator": { "total": requested.len(), "required": requested.len(), "accounted": accounted, "synthesized": synthesized },
        "coverageGaps": sorted(gaps),
    })
}

pub trait OsProbeHost {
    fn probe(&self, request: &Value) -> Value;
}

pub fn execute_desktop_os_matrix(host: Option<&dyn OsProbeHost>, input: &Value) -> Value {
    let Some(host) = host else { return compile_desktop_os_matrix(input) };
    let required: Vec<Value> = match get(input, "required").as_array() {
        Some(arr) => arr.clone(),
        None => DESKTOP_OS_CASES.iter().map(|s| json!(s)).collect(),
    };
    let binding = get(input, "binding").clone();
    let binding_obj = if binding.is_object() { binding } else { json!({}) };
    let mut receipts = Vec::new();
    for id in &required {
        let mut request = binding_obj.clone();
        request["id"] = id.clone();
        let mut probe = host.probe(&request);
        probe["id"] = id.clone();
        probe["terminal"] = json!(true);
        receipts.push(probe);
    }
    let mut merged = input.clone();
    merged["required"] = json!(required);
    merged["cases"] = json!(receipts);
    compile_desktop_os_matrix(&merged)
}

// ---------------------------------------------------------------------
// performance/index.mjs
// ---------------------------------------------------------------------

pub const PERFORMANCE_CASES: &[&str] = &[
    "cold-start", "first-usable", "input", "background-job", "memory-idle", "memory-peak", "cpu-wakeups",
    "gpu-fallback", "disk-network", "energy", "duration", "low-end", "fault",
];

fn environment_gaps(environment: &Value) -> Vec<String> {
    let mut gaps = Vec::new();
    if falsy(get(environment, "os")) || falsy(get(environment, "hardware")) {
        gaps.push("measurement-environment-incomplete".to_string());
    }
    if falsy(get(environment, "hardwareClass")) {
        gaps.push("hardware-class-missing".to_string());
    }
    let cpu_ok = get_f64(environment, "cpuCores").is_some_and(|v| v >= 1.0);
    let ram_ok = get_f64(environment, "ramMb").is_some_and(|v| v >= 1.0);
    if !cpu_ok || !ram_ok || falsy(get(environment, "diskType")) {
        gaps.push("hardware-spec-incomplete".to_string());
    }
    if falsy(get(environment, "profilingTool")) {
        gaps.push("profiling-tool-missing".to_string());
    }
    if get_f64(environment, "energyBudgetMw").is_none() {
        gaps.push("energy-budget-missing".to_string());
    }
    gaps
}

struct MeasurementEvidence {
    gaps: Vec<String>,
    samples: Vec<Value>,
    repeat_count: usize,
}

fn measurement_evidence(item: &Value) -> MeasurementEvidence {
    let id = id_of(item);
    let mut gaps = Vec::new();
    let samples: Vec<Value> = get_array(item, "samples")
        .iter()
        .filter(|v| v.as_f64().is_some())
        .cloned()
        .collect();
    let p95 = get(item, "percentiles").get("p95").and_then(Value::as_f64);
    if falsy(get(item, "id")) || falsy(get(item, "unit")) || samples.len() < 3 || p95.is_none() {
        gaps.push(format!("measurement-incomplete:{id}"));
    }
    if get_f64(item, "budget").is_none() || falsy(get(item, "profileArtifact")) || get_f64(item, "variance").is_none() {
        gaps.push(format!("measurement-budget-missing:{id}"));
    }
    if !get_f64(item, "durationSeconds").is_some_and(|v| v >= 1.0) {
        gaps.push(format!("measurement-duration-missing:{id}"));
    }
    let repeat_count = samples.len();
    MeasurementEvidence { gaps, samples, repeat_count }
}

pub fn evaluate_desktop_performance(input: &Value) -> Value {
    let artifact = get(input, "artifact").clone();
    let artifact = if artifact.is_null() { json!({}) } else { artifact };
    let environment = get(input, "environment").clone();
    let environment = if environment.is_null() { json!({}) } else { environment };
    let measurements: Vec<Value> = get_array(input, "measurements").to_vec();
    let soak = get(input, "soak").clone();

    let mut gaps = environment_gaps(&environment);
    let digest_ok = get_str(&artifact, "digest").is_some_and(is_sha256_digest);
    if get_str(&artifact, "build") != Some("release") || !digest_ok {
        gaps.push("release-artifact-unproven".to_string());
    }

    let mut normalized: Vec<Value> = Vec::new();
    for item in &measurements {
        let evidence = measurement_evidence(item);
        gaps.extend(evidence.gaps);
        let mut merged = item.clone();
        merged["samples"] = json!(evidence.samples);
        merged["repeatCount"] = json!(evidence.repeat_count);
        normalized.push(merged);
    }
    if measurements.is_empty() {
        gaps.push("measurement-denominator-empty".to_string());
    }
    for id in PERFORMANCE_CASES {
        if !measurements.iter().any(|item| get_str(item, "id") == Some(*id)) {
            gaps.push(format!("measurement-case-missing:{id}"));
        }
    }
    if soak.is_null() {
        gaps.push("soak-evidence-missing".to_string());
    } else if get_str(&soak, "status") == Some("pass") {
        if !get_f64(&soak, "hours").is_some_and(|h| h >= 8.0) {
            gaps.push("soak-duration-incomplete".to_string());
        }
    } else {
        let tag = get_str(&soak, "capabilityGap").or_else(|| get_str(&soak, "status")).unwrap_or("unproven");
        gaps.push(format!("soak-{tag}"));
    }

    let coverage_gaps = dedup_sorted(gaps);
    let status = if coverage_gaps.is_empty() {
        "pass"
    } else if coverage_gaps.iter().all(|g| g.starts_with("soak-")) {
        "partial"
    } else {
        "unproven"
    };

    json!({
        "schemaVersion": 1, "kind": "legion-desktop-performance", "status": status, "terminal": true,
        "artifact": artifact, "environment": environment, "measurements": normalized, "soak": soak,
        "denominator": {
            "total": PERFORMANCE_CASES.len(),
            "accounted": normalized.len(),
            "hardwareClass": get(&environment, "hardwareClass"),
            "profilingTool": get(&environment, "profilingTool"),
            "soakHours": get(&soak, "hours"),
            "budgetExceeded": get(&soak, "budgetExceeded"),
        },
        "coverageGaps": coverage_gaps,
    })
}

pub trait PerformanceHost {
    fn measure(&self, request: &Value) -> Value;
    fn soak(&self, request: &Value) -> Value;
}

pub fn execute_desktop_performance(host: Option<&dyn PerformanceHost>, artifact: &Value, environment: &Value, budgets: &Value) -> Value {
    let Some(host) = host else {
        return evaluate_desktop_performance(&json!({ "artifact": artifact, "environment": environment }));
    };
    let measurements: Vec<Value> = PERFORMANCE_CASES
        .iter()
        .map(|id| host.measure(&json!({ "id": id, "budget": get(budgets, id) })))
        .collect();
    let soak = host.soak(&json!({ "minimumHours": 8 }));
    evaluate_desktop_performance(&json!({ "artifact": artifact, "environment": environment, "measurements": measurements, "soak": soak }))
}

// ---------------------------------------------------------------------
// runner/index.mjs
// ---------------------------------------------------------------------

pub const DESKTOP_FRAMEWORKS: &[&str] = &["electron", "tauri", "apple", "dotnet", "qt-native", "flutter"];

fn desktop_adapter(framework: &str) -> Option<Value> {
    match framework {
        "electron" => Some(json!({ "processRoles": ["main", "renderer"], "nativeSurface": "window" })),
        "tauri" => Some(json!({ "processRoles": ["main", "webview"], "nativeSurface": "window" })),
        "apple" => Some(json!({ "processRoles": ["application"], "nativeSurface": "nswindow" })),
        "dotnet" => Some(json!({ "processRoles": ["application"], "nativeSurface": "hwnd" })),
        "qt-native" => Some(json!({ "processRoles": ["application"], "nativeSurface": "qwindow" })),
        "flutter" => Some(json!({ "processRoles": ["application"], "nativeSurface": "engine-view" })),
        _ => None,
    }
}

fn same_artifact(expected: &Value, actual: &Value) -> bool {
    get(expected, "path") == get(actual, "path") && get(expected, "digest") == get(actual, "digest")
}

pub fn collect_desktop_runtime(input: &Value) -> Value {
    let target = get(input, "target").clone();
    let target = if target.is_null() { json!({}) } else { target };
    let artifact = get(input, "artifact").clone();
    let artifact = if artifact.is_null() { json!({}) } else { artifact };
    let capability = get(input, "capability").clone();
    let capability = if capability.is_null() { json!({}) } else { capability };
    let observations = get(input, "observations").clone();
    let observations = if observations.is_null() { json!({}) } else { observations };

    let mut gaps: Vec<String> = Vec::new();
    if falsy(get(&target, "id")) {
        gaps.push("target-id-missing".to_string());
    }
    let framework = get_str(&target, "framework");
    if !framework.is_some_and(|f| DESKTOP_FRAMEWORKS.contains(&f)) {
        gaps.push("framework-unsupported".to_string());
    }
    let digest_ok = get_str(&artifact, "digest").is_some_and(is_sha256_digest);
    if falsy(get(&artifact, "path")) || !digest_ok {
        gaps.push("artifact-binding-incomplete".to_string());
    }
    let capability_receipt = get(&capability, "receipt");
    if get_str(&capability, "status") != Some("available") || !get_true(capability_receipt, "cleanEnvironment") {
        let status = get_str(&capability, "status").unwrap_or("missing");
        gaps.push(format!("native-capability-{status}"));
    }
    if !get_true(capability_receipt, "nativeSurface") || get_true(&observations, "browserOnly") {
        gaps.push("native-surface-unproven".to_string());
    }
    let observations_receipt = get(&observations, "receipt");
    if get_str(&observations, "source") != Some("native-host") || !get_true(observations_receipt, "terminal") {
        gaps.push("native-observation-receipt-missing".to_string());
    }
    let executable = get(&observations, "executable");
    if truthy(executable) && !same_artifact(&artifact, executable) {
        gaps.push("executable-binding-mismatch".to_string());
    }
    if !truthy(executable) && !get_true(&observations, "browserOnly") {
        gaps.push("executable-observation-missing".to_string());
    }
    if get_array(&observations, "processes").is_empty() {
        gaps.push("process-inventory-empty".to_string());
    }
    if get_array(&observations, "windows").is_empty() {
        gaps.push("window-inventory-empty".to_string());
    }
    if !get_true(get(&observations, "shutdown"), "clean") {
        gaps.push("shutdown-unproven".to_string());
    }
    if !get_true(get(&observations, "environment"), "isolated") {
        gaps.push("environment-isolation-unproven".to_string());
    }

    let components = json!({
        "processes": get_array(&observations, "processes"),
        "windows": get_array(&observations, "windows"),
        "helpers": get_array(&observations, "helpers"),
        "services": get_array(&observations, "services"),
        "sidecars": get_array(&observations, "sidecars"),
        "localServers": get_array(&observations, "localServers"),
        "webviews": get_array(&observations, "webviews"),
        "gpuProcesses": get_array(&observations, "gpuProcesses"),
    });

    let status = if gaps.iter().any(|g| g == "executable-binding-mismatch") {
        "unproven"
    } else if !gaps.is_empty() {
        "partial"
    } else {
        "pass"
    };

    json!({
        "schemaVersion": 1, "kind": "legion-desktop-runtime", "status": status, "terminal": true,
        "binding": {
            "targetId": get(&target, "id"), "artifactPath": get(&artifact, "path"),
            "artifactDigest": get(&artifact, "digest"), "framework": get(&target, "framework"),
        },
        "components": components,
        "lifecycle": {
            "startup": get(&observations, "startup"), "firstUsable": get(&observations, "firstUsable"),
            "shutdown": get(&observations, "shutdown"), "crashes": get_array(&observations, "crashes"),
            "orphans": get_array(&observations, "orphans"),
        },
        "environment": get(&observations, "environment"),
        "logs": get_array(&observations, "logs"),
        "coverageGaps": dedup_sorted(gaps),
    })
}

pub trait DesktopRuntimeHost {
    fn launch(&self, request: &Value) -> Value;
    fn attach(&self, request: &Value) -> Value;
    fn supports_attach(&self) -> bool {
        true
    }
    fn supports_launch(&self) -> bool {
        true
    }
}

pub fn execute_desktop_runtime(host: Option<&dyn DesktopRuntimeHost>, target: &Value, artifact: &Value, capability: &Value, attach: bool) -> Value {
    let usable = match (&host, attach) {
        (Some(h), true) => h.supports_attach(),
        (Some(h), false) => h.supports_launch(),
        (None, _) => false,
    };
    if !usable {
        let mut capability_fallback = capability.clone();
        if capability_fallback.is_null() {
            capability_fallback = json!({});
        }
        if get(&capability_fallback, "status").is_null() {
            capability_fallback["status"] = json!("unavailable");
        }
        return collect_desktop_runtime(&json!({
            "target": target, "artifact": artifact, "capability": capability_fallback,
            "observations": { "browserOnly": false },
        }));
    }
    let host = host.unwrap();
    let framework = get_str(target, "framework").unwrap_or("");
    let adapter = desktop_adapter(framework).unwrap_or_else(|| json!({}));
    let mut adapter_with_id = adapter;
    adapter_with_id["id"] = json!(framework);
    let request = json!({
        "target": target, "artifact": artifact, "adapter": adapter_with_id,
        "capture": ["executable", "processes", "windows", "helpers", "services", "sidecars", "localServers",
                    "webviews", "gpuProcesses", "startup", "firstUsable", "logs", "crashes", "orphans",
                    "shutdown", "environment", "receipt"],
    });
    let observations = if attach { host.attach(&request) } else { host.launch(&request) };
    collect_desktop_runtime(&json!({ "target": target, "artifact": artifact, "capability": capability, "observations": observations }))
}

// ---------------------------------------------------------------------
// updater/index.mjs
// ---------------------------------------------------------------------

const UPDATER_CHECKS: &[&str] = &["application", "metadata", "payload", "timestamp"];
pub const UPDATE_CASES: &[&str] = &[
    "corrupt-manifest", "forged-payload", "redirect", "local-replacement", "insufficient-disk",
    "locked-files", "interruption-resume", "updater-crash", "failed-install", "rollback",
    "bad-release-pause", "staged-rollout", "kill-switch", "offline-grace", "self-update",
];
const FORGED_CALLER_BOOLS: &[&str] = &["forgedCaller", "fakeCaller", "spoofedCaller", "impersonatedCaller"];

fn verified(value: &Value, digest: &Value) -> bool {
    get_str(value, "status") == Some("pass") && get(value, "artifactDigest") == digest
}

pub fn evaluate_updater_evidence(input: &Value) -> Value {
    let artifact = get(input, "artifact").clone();
    let artifact = if artifact.is_null() { json!({}) } else { artifact };
    let verification = get(input, "verification").clone();
    let verification = if verification.is_null() { json!({}) } else { verification };
    let attempts: Vec<Value> = get_array(input, "attempts").to_vec();
    let promotion = get(input, "promotion").clone();
    let promotion = if promotion.is_null() { json!({}) } else { promotion };

    let mut gaps: Vec<String> = Vec::new();
    if let Some(map) = obj(&artifact) {
        for key in map.keys() {
            if FORGED_CALLER_BOOLS.contains(&key.as_str()) {
                gaps.push(format!("forged-caller-boolean:{key}"));
            }
        }
    }
    let digest = get(&artifact, "digest");
    for check in UPDATER_CHECKS {
        if !verified(get(&verification, check), digest) {
            gaps.push(format!("signature-{check}-unproven"));
        }
    }
    if falsy(get(&artifact, "publisher")) {
        gaps.push("publisher-identity-unproven".to_string());
    }
    let bypass = attempts.iter().any(|item| get_bool(item, "verificationPassed") == Some(false) && get_true(item, "executed"));
    if bypass {
        gaps.push("verification-bypass".to_string());
    }
    for item in &attempts {
        if !get_true(item, "terminal") {
            gaps.push(format!("attempt-nonterminal:{}", id_of(item)));
        }
    }
    for id in UPDATE_CASES {
        if !attempts.iter().any(|item| get_str(item, "id") == Some(*id) && get_true(item, "terminal")) {
            gaps.push(format!("updater-case-missing:{id}"));
        }
    }
    let digests = [get(&promotion, "qaDigest"), get(&promotion, "updateDigest"), get(&promotion, "distributedDigest")];
    let promotion_specified = digests.iter().any(|d| truthy(d));
    let promotion_equivalent = promotion_specified && digests.iter().all(|d| *d == digest);
    if !promotion_specified {
        gaps.push("promotion-evidence-missing".to_string());
    } else if !promotion_equivalent {
        gaps.push("promotion-artifact-mismatch".to_string());
    }
    if !get_true(get(&promotion, "privilegedService"), "revalidated") {
        gaps.push("privileged-revalidation-unproven".to_string());
    }
    if falsy(get(&promotion, "channel")) || falsy(get(&promotion, "rollout")) {
        gaps.push("channel-rollout-unproven".to_string());
    }
    let qa_gate = get_str(&promotion, "qaGate");
    if (qa_gate == Some("mandatory") || qa_gate.is_none()) && !get_true(&promotion, "mandatory") {
        gaps.push("mandatory-qa-promotion-missing".to_string());
    }
    let logs = get_array(&promotion, "logs");
    if logs.iter().any(|v| looks_sensitive(&js_string_coerce(v))) {
        gaps.push("updater-log-sensitive".to_string());
    }
    let verification_failed = UPDATER_CHECKS.iter().any(|check| get_str(get(&verification, check), "status") == Some("fail"));
    let has_forged_caller = gaps.iter().any(|g| g.starts_with("forged-caller-boolean:"));
    let stop_ship = verification_failed || bypass || has_forged_caller;
    let status = if stop_ship {
        "fail"
    } else if !gaps.is_empty() {
        "unproven"
    } else {
        "pass"
    };

    json!({
        "schemaVersion": 1, "kind": "legion-desktop-updater", "status": status, "terminal": true,
        "artifact": artifact, "verification": verification, "attempts": attempts,
        "promotionEquivalent": promotion_equivalent, "stopShip": stop_ship, "coverageGaps": sorted(gaps),
    })
}

pub trait UpdaterHost {
    fn exercise(&self, request: &Value) -> Value;
}

pub fn execute_updater_evidence(host: Option<&dyn UpdaterHost>, artifact: &Value, verification: &Value, promotion: &Value) -> Value {
    let Some(host) = host else {
        return evaluate_updater_evidence(&json!({ "artifact": artifact, "verification": verification, "promotion": promotion }));
    };
    let attempts: Vec<Value> = UPDATE_CASES
        .iter()
        .map(|id| host.exercise(&json!({ "id": id, "artifact": artifact, "promotion": promotion })))
        .collect();
    evaluate_updater_evidence(&json!({ "artifact": artifact, "verification": verification, "promotion": promotion, "attempts": attempts }))
}

// ---------------------------------------------------------------------
// windows/index.mjs
// ---------------------------------------------------------------------

pub const WINDOWS_CASES: &[&str] = &[
    "dpi-awareness", "unicode-long-path", "appdata-registry-acl", "authenticode", "smartscreen-defender",
    "dll-search", "uac", "services-tasks", "quoted-registration", "installer", "remote-desktop",
    "edr-assumptions",
];

pub fn evaluate_windows_platform(input: &Value) -> Value {
    let matrix = get(input, "matrix").clone();
    let artifact = get(input, "artifact").clone();
    let artifact = if artifact.is_null() { json!({}) } else { artifact };
    let checks: Vec<Value> = get_array(input, "checks").to_vec();
    let capability = get(input, "capability").clone();
    let capability = if capability.is_null() { json!({ "status": "available" }) } else { capability };

    let bound = bound_matrix("windows", &matrix);
    let mut gaps: Vec<String> = Vec::new();
    if falsy(get(&bound, "version")) || falsy(get(&bound, "architecture")) {
        gaps.push("windows-matrix-incomplete".to_string());
    }
    if get_str(&capability, "status") != Some("available") {
        let reason = get_str(&capability, "reason").or_else(|| get_str(&capability, "status")).unwrap_or("missing");
        gaps.push(format!("windows-capability-{reason}"));
    }
    for check in &checks {
        let cid = id_of(check);
        if !get_true(check, "terminal") {
            gaps.push(format!("windows-check-nonterminal:{cid}"));
        }
        if (cid == "authenticode" || cid == "installer")
            && (!get_true(&artifact, "final") || get(check, "artifactDigest") != get(&artifact, "digest"))
        {
            gaps.push(format!("windows-final-artifact-unproven:{cid}"));
        }
    }
    for id in WINDOWS_CASES {
        if !checks.iter().any(|c| get_str(c, "id") == Some(*id) && get_true(c, "terminal")) {
            gaps.push(format!("windows-case-missing:{id}"));
        }
    }
    json!({
        "schemaVersion": 1, "kind": "legion-desktop-windows",
        "status": if gaps.is_empty() { "pass" } else { "unproven" }, "terminal": true,
        "matrix": bound, "artifact": artifact, "receipts": checks, "coverageGaps": sorted(gaps),
    })
}

pub fn execute_windows_platform(host: Option<&dyn PlatformCheckHost>, input: &Value) -> Value {
    let Some(host) = host else { return evaluate_windows_platform(input) };
    let artifact = get(input, "artifact");
    let checks: Vec<Value> = WINDOWS_CASES.iter().map(|id| host.check(&json!({ "os": "windows", "id": id, "artifact": artifact }))).collect();
    let mut merged = input.clone();
    merged["checks"] = json!(checks);
    evaluate_windows_platform(&merged)
}

// ---------------------------------------------------------------------
// worker/index.mjs
// ---------------------------------------------------------------------

pub const SERVICE_RUNTIME_SCENARIOS: &[&str] = &[
    "api-contract", "identity-authorization", "data-effect", "timeout-retry", "idempotency",
    "rate-cost-limit", "queue-ordering", "queue-duplicate", "poison-message", "backpressure",
    "worker-restart", "graceful-shutdown", "health-readiness", "migration", "capacity",
    "fault-recovery", "observability",
];
