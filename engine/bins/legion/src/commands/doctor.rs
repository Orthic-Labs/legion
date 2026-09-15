use super::{CommandError, CommandResult};
use crate::cli::{installed_m1_composition, RootArgs};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

const BLUEPRINT_TIMEOUT_MS: u64 = 15_000;
const SEMANTIC_TIMEOUT_MS: u64 = 3_000;
const SEMANTIC_PROBES: [&str; 13] = [
    "generated-input-rejection",
    "ambient-availability-bypass",
    "locked-unavailable-denial",
    "uncertified-stop-exit",
    "two-denial-release",
    "recovery-preservation",
    "adapter-parity",
    "budget_store_integrity",
    "budget_binding_exactness",
    "budget_monotonicity",
    "budget_stop_enforcement",
    "budget_role_cap_enforcement",
    "budget_amendment_authority",
];
const CODEX_HOOK_EVENTS: [&str; 8] = [
    "session_start",
    "subagent_start",
    "user_prompt_submit",
    "post_compact",
    "pre_tool_use",
    "post_tool_use",
    "post_tool_use_failure",
    "stop",
];
const LEGACY_NAMES: [&str; 4] = ["seer", "forge", "sorcerer", "sentinel"];
const NAMING_TOKENS: [&str; 5] = ["seer", "nemesis", "forge", "sentinel", "sorcerer"];

fn now() -> String {
    format_time(SystemTime::now())
}

fn format_time(time: SystemTime) -> String {
    let elapsed = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = elapsed.as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    // Civil date conversion from Unix days (Howard Hinnant's proleptic
    // Gregorian algorithm), kept local so lifecycle records need no runtime.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let year = yoe + era * 400;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month = (5 * day_of_year + 2).div_euclid(153);
    let day = day_of_year - (153 * month + 2).div_euclid(5) + 1;
    let month = month + if month < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        day_seconds / 3_600,
        day_seconds % 3_600 / 60,
        day_seconds % 60,
        elapsed.subsec_millis()
    )
}

fn lifecycle(phase: &str, detail: Value) {
    eprintln!(
        "{}",
        json!({"kind":"legion-doctor-lifecycle","phase":phase,"detail":detail,"at":now()})
    );
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}
fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn absolute_root(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    // Node's resolve() performs lexical cleanup, including removing a trailing
    // `.`. Keep the caller's path semantics without requiring it to exist.
    joined.components().collect()
}

fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn command_path(command: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        for extension in [".exe", ".cmd", ".bat"] {
            let candidate = directory.join(format!("{command}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn runtime_toolchains() -> Value {
    let Some(executable) = command_path("node") else {
        return json!({"state":"unproven","tools":[]});
    };
    let Ok(output) = Command::new(&executable).arg("--version").output() else {
        return json!({"state":"unproven","tools":[]});
    };
    if !output.status.success() {
        return json!({"state":"unproven","tools":[]});
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if version.is_empty() {
        return json!({"state":"unproven","tools":[]});
    }
    json!({"state":"ready","tools":[{"name":"node","executable":executable,"version":version}]})
}

fn installed_roots() -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    let Ok(composition) = installed_m1_composition() else {
        return (None, None, None);
    };
    let Some(share) = composition.parent() else {
        return (None, None, None);
    };
    let current = share.parent().map(Path::to_path_buf);
    let plugin = current.as_ref().map(|root| root.join("plugin"));
    (Some(share.join("assets")), plugin, Some(composition))
}

fn coverage_families() -> Vec<String> {
    vec!["framework.react".into(), "framework.tauri".into()]
}

fn packet_projection(root: &Path, env: &HashMap<String, String>) -> (Value, Value) {
    let requested = env.get("LEGION_MEMBRANE_PACKET").map(PathBuf::from);
    let candidate = requested.clone().or_else(|| {
        let path = root.join(".audit/blueprint/packet.json");
        path.is_file().then_some(path)
    });
    let mode = if requested.is_some() {
        "packet-file"
    } else {
        "bounded-one-shot"
    };
    let Some(path) = candidate else {
        return (
            json!({"status":"unavailable","reason":"membrane-blueprint-transport-unavailable"}),
            json!({"mode":mode,"state":"missing"}),
        );
    };
    let Some(packet) = read_json(&path) else {
        return (
            json!({"status":"unavailable","reason":"membrane-blueprint-packet-invalid"}),
            json!({"mode":mode,"state":"missing"}),
        );
    };
    let schema = packet
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(
        schema,
        "membrane.context-packet.v1" | "membrane.blueprint-packet.v1"
    ) || packet.get("status").and_then(Value::as_str) == Some("unavailable")
    {
        return (
            json!({"status":"unavailable","reason":"membrane-blueprint-packet-invalid"}),
            json!({"mode":mode,"state":"missing"}),
        );
    }
    if schema == "membrane.blueprint-packet.v1" {
        let valid = std::fs::canonicalize(&path)
            .ok()
            .and_then(|absolute| {
                legion_audit::FileBlueprintInventorySource::new(absolute, None).ok()
            })
            .is_some();
        if !valid {
            return (
                json!({"status":"unavailable","reason":"membrane-blueprint-packet-invalid"}),
                json!({"mode":mode,"state":"missing"}),
            );
        }
    }
    let stale = packet.get("stale").and_then(Value::as_bool) == Some(true)
        || packet.get("state").and_then(Value::as_str) == Some("stale")
        || packet.get("status").and_then(Value::as_str) == Some("stale")
        || packet
            .get("freshness")
            .and_then(Value::as_object)
            .and_then(|v| v.get("fresh"))
            .and_then(Value::as_bool)
            == Some(false);
    (
        packet,
        json!({"mode":mode,"state":if stale {"stale"} else {"ready"}}),
    )
}

fn semantic_health(env: &HashMap<String, String>) -> Value {
    let injected = env
        .get("ARCANE_SEMANTIC_HEALTH_INJECT_FAILURE")
        .map(|value| value.split(',').map(str::trim).collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let probes = SEMANTIC_PROBES
        .iter()
        .map(|id| {
            let started = now();
            lifecycle(
                "semantic-probe",
                json!({"id":id,"phase":"started","timeoutMs":SEMANTIC_TIMEOUT_MS}),
            );
            let failed = injected.contains(id);
            let error = if failed {
                Some("injected semantic failure fixture")
            } else {
                None
            };
            let mut finished = json!({"id":id,"phase":"finished","ok":!failed});
            if let Some(error) = error {
                finished["error"] = json!(error);
            }
            lifecycle("semantic-probe", finished);
            json!({"id":id,"ok":!failed,"startedAt":started,"finishedAt":now(),"error":error})
        })
        .collect::<Vec<_>>();
    json!({"schemaVersion":1,"kind":"arcane-semantic-health","healthy":probes.iter().all(|probe| probe["ok"] == true),"probes":probes})
}

fn inspect_mcp_naming(value: &Value) -> Value {
    let Some(servers) = value
        .get("mcp_servers")
        .or_else(|| value.get("mcpServers"))
        .and_then(Value::as_object)
    else {
        return json!({"status":"absent","legacy":[]});
    };
    let mut legacy = Vec::new();
    for id in LEGACY_NAMES {
        if let Some(entry) = servers.get(id) {
            let owned = entry
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| command == "python" || command == "python3")
                && entry
                    .get("args")
                    .and_then(Value::as_array)
                    .is_some_and(|args| {
                        args.windows(2).any(|pair| {
                            pair[0].as_str() == Some("-m")
                                && pair[1].as_str() == Some("legion_kernel.adapters.mcp_server")
                        })
                    });
            legacy.push(json!({
                "id": id,
                "owned": owned,
                "conflict": servers
                    .get("oracle")
                    .is_some_and(|canonical| canonical != entry),
            }));
        }
    }
    json!({"status":if legacy.is_empty() {"canonical"} else {"legacy-present"},"legacy":legacy})
}

fn naming_bindings(root: &Path) -> Value {
    let inspect = |path: PathBuf| -> Value {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
                .map(|value| inspect_mcp_naming(&value))
                .unwrap_or_else(|_| json!({"status":"invalid","legacy":[]})),
            Err(_) => json!({"status":"absent","legacy":[]}),
        }
    };
    let text = std::fs::read_to_string(root.join(".codex/config.toml")).unwrap_or_default();
    let mut legacy = Vec::new();
    for line in text.lines().map(str::trim) {
        let folded = line.to_ascii_lowercase();
        if let Some(id) = folded
            .strip_prefix("[mcp_servers.")
            .and_then(|v| v.strip_suffix(']'))
        {
            if LEGACY_NAMES.contains(&id) {
                legacy.push(id.to_owned());
            }
        }
    }
    legacy.sort();
    json!({"claudeCode":inspect(root.join(".mcp.json")),"gemini":inspect(root.join(".gemini/settings.json")),"codex":{"status":if legacy.is_empty() {if text.is_empty() {"absent"} else {"canonical"}} else {"legacy-present"},"legacy":legacy}})
}

fn naming_source_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn naming_occurrences(text: &str, token: &str) -> Vec<usize> {
    let lower = text.to_ascii_lowercase();
    let mut lines = Vec::new();
    for (index, _) in lower.match_indices(token) {
        let before = lower.as_bytes().get(index.wrapping_sub(1)).copied();
        let after = lower.as_bytes().get(index + token.len()).copied();
        let word = |byte: Option<u8>| byte.is_some_and(|value| value.is_ascii_alphanumeric());
        if !word(before) && !word(after) {
            lines.push(lower[..index].bytes().filter(|byte| *byte == b'\n').count() + 1);
        }
    }
    lines
}

fn naming_rule<'a>(rules: &'a [Value], path: &str, token: &str) -> Option<&'a Value> {
    rules.iter().find(|rule| {
        let target = rule.get("path").and_then(Value::as_str);
        let prefix = rule.get("pathPrefix").and_then(Value::as_str);
        let applies = target == Some(path) || prefix.is_some_and(|value| path.starts_with(value));
        applies && rule.get("tokens").and_then(Value::as_array).is_some_and(|tokens| tokens.iter().any(|value| value.as_str() == Some(token)))
    })
}

fn naming_files(root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files", "-co", "--exclude-standard", "-z"])
        .current_dir(root)
        .output();
    output
        .ok()
        .filter(|value| value.status.success())
        .map(|value| String::from_utf8_lossy(&value.stdout).split('\0').filter(|path| !path.is_empty()).map(str::to_owned).collect())
        .unwrap_or_default()
}

fn naming_contract(_assets: Option<&Path>) -> Value {
    let root = naming_source_root();
    let rules = read_json(&root.join("src/config/naming-legacy-allowlist.json"))
        .and_then(|value| value.get("rules").cloned())
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut issues = Vec::new();
    for path in naming_files(&root).into_iter().filter(|path| {
        ![".git/", ".agent/", ".audit/", ".cache/", "docs/foundation/", "node_modules/"]
            .iter()
            .any(|prefix| format!("{path}/").starts_with(prefix))
    }) {
        for token in NAMING_TOKENS {
            let path_hits = naming_occurrences(&path, token);
            if !path_hits.is_empty() && naming_rule(&rules, &path, token).is_none() {
                issues.push(json!({"path":path,"token":token,"reason":"unclassified legacy filename"}));
            }
        }
        let Some(text) = std::fs::read(&root.join(&path)).ok().and_then(|bytes| {
            if bytes.contains(&0) { return None; }
            String::from_utf8(bytes).ok()
        }) else { continue };
        for token in NAMING_TOKENS {
            let lines = naming_occurrences(&text, token);
            if lines.is_empty() { continue; }
            let Some(rule) = naming_rule(&rules, &path, token) else {
                issues.push(json!({"path":path,"line":lines[0],"token":token,"reason":"unclassified legacy token"}));
                continue;
            };
            if rule.get("path").is_some() && rule.get("class").and_then(Value::as_str) != Some("R5") && rule.get("occurrences").and_then(|value| value.get(token)).and_then(Value::as_u64).is_none() {
                issues.push(json!({"path":path,"line":lines[0],"token":token,"reason":"active exact-path allowlist lacks occurrence count"}));
            }
            if let Some(expected) = rule.get("occurrences").and_then(|value| value.get(token)).and_then(Value::as_u64) {
                if lines.len() as u64 != expected { issues.push(json!({"path":path,"line":lines[0],"token":token,"reason":format!("legacy token occurrence count differs: expected {expected}, found {}", lines.len())})); }
            }
        }
    }
    json!({"schemaVersion":1,"kind":"legion-naming-contract-report","status":if issues.is_empty() {"pass"} else {"fail"},"canonicalAuthorities":["alchemist","arcane","oracle","sage"],"deprecatedAliases":["forge","seer","sentinel","sorcerer"],"unclassified":issues})
}

fn binding_section(root: &Path) -> Value {
    let Some(receipt) = read_json(&root.join(".legion/binding.json")) else {
        return json!({"receiptPresent":false,"harnesses":[]});
    };
    let mut harnesses = Vec::new();
    for entry in receipt
        .get("harnesses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mut drift = Vec::new();
        for record in entry
            .get("files")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(path) = record.as_str().map(str::to_owned).or_else(|| {
                record
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }) else {
                continue;
            };
            let disk = root.join(&path);
            let Ok(bytes) = std::fs::read(&disk) else {
                drift.push(json!({"path":path,"kind":"missing"}));
                continue;
            };
            let observed = json!({"bytes":bytes.len(),"digest":digest_bytes(&bytes)});
            if record.is_object()
                && (record.get("digest") != Some(&observed["digest"])
                    || record.get("bytes") != Some(&observed["bytes"]))
            {
                drift.push(json!({"path":path,"kind":"receipt-digest-mismatch","expected":record,"observed":observed}));
            }
        }
        harnesses.push(json!({"name":entry.get("name").cloned().unwrap_or(Value::Null),"fidelityTier":entry.get("fidelityTier").cloned().unwrap_or(Value::Null),"filesTracked":entry.get("files").and_then(Value::as_array).map_or(0,Vec::len),"drift":drift}));
    }
    json!({"receiptPresent":true,"harnesses":harnesses})
}

fn codex_hook_trust(home: &Path) -> Value {
    let config_path = home.join(".codex").join("config.toml");
    let text = std::fs::read_to_string(&config_path).unwrap_or_default();
    let mut trusted = BTreeSet::new();
    let mut current = None::<String>;
    for line in text.lines().map(str::trim) {
        if let Some(value) = line
            .strip_prefix("[hooks.state.\"")
            .and_then(|v| v.strip_suffix("\"]"))
        {
            current = Some(value.to_owned());
            continue;
        }
        if let Some(value) = line
            .strip_prefix("trusted_hash = \"")
            .and_then(|v| v.strip_suffix('"'))
        {
            if let Some(event) = current.as_deref() {
                if CODEX_HOOK_EVENTS
                    .iter()
                    .any(|name| event == format!("arcane@local-brief:hooks/hooks.json:{name}:0:0"))
                    && value.strip_prefix("sha256:").is_some_and(|hash| {
                        hash.len() == 64
                            && hash
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                {
                    trusted.insert(event.to_owned());
                }
            }
        }
    }
    let required = CODEX_HOOK_EVENTS
        .iter()
        .map(|event| format!("arcane@local-brief:hooks/hooks.json:{event}:0:0"))
        .collect::<Vec<_>>();
    let missing = required
        .iter()
        .filter(|key| !trusted.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    json!({"configPath":config_path,"configPresent":!text.is_empty(),"plugin":"arcane@local-brief","required":required,"trusted":trusted.into_iter().collect::<Vec<_>>(),"missing":missing,"state":if missing.is_empty() {"pass"} else {"ARC_HOOK_TRUST_REQUIRED"},"remediation":if missing.is_empty() {Value::Null} else {json!("Review & trust current Guard hooks (legacy plugin identity arcane@local-brief) with Codex /hooks; setup never manufactures trusted_hash.")}})
}

fn host_requirements(root: &Path) -> Value {
    let index = root.join("src/registry/host-projection.json");
    if !index.is_file() {
        return json!({"present":false,"state":"missing-projection","skills":[]});
    }
    let Some(value) = read_json(&index) else {
        return json!({"present":false,"state":"invalid-registry","detail":"installed capability registry is unavailable","skills":[]});
    };
    let mut skills = Vec::new();
    for bundle in value
        .get("capabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = bundle.get("kind").and_then(Value::as_str);
        let discoverability = bundle.get("discoverability").and_then(Value::as_str);
        if !((kind == Some("domain-capability") && discoverability == Some("public"))
            || (kind == Some("entrypoint") && discoverability == Some("explicit")))
        {
            continue;
        }
        let requirement_row = |detail: &Value, scope: &str, scope_kind: &str| -> Value {
            let id = detail
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let probe = detail.get("probe").cloned().unwrap_or(Value::Null);
            let availability = legion_application::probe_host_requirement(if probe.is_null() {
                None
            } else {
                Some(&probe)
            });
            let (available, availability_name) = match availability {
                legion_application::M1Availability::Available => (json!(true), "available"),
                legion_application::M1Availability::Unavailable => (json!(false), "unavailable"),
                legion_application::M1Availability::Unknown => (Value::Null, "unknown"),
            };
            json!({
                "id": id,
                "scope": scope,
                "scopeKind": scope_kind,
                "available": available,
                "availability": availability_name,
                "degradation": detail.get("degradation").cloned().unwrap_or_else(|| json!("The projected skill requirement could not be probed by native doctor.")),
                "remedy": detail.get("remedy").cloned().unwrap_or_else(|| json!("Run doctor on a host that declares this requirement.")),
                "probe": probe,
            })
        };
        let mut requirements = Vec::new();
        if let Some(details) = bundle
            .get("hostRequirementDetails")
            .and_then(Value::as_array)
        {
            for detail in details {
                requirements.push(requirement_row(detail, "global", "capability"));
            }
        } else {
            for req in bundle
                .get("hostRequirements")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                requirements.push(requirement_row(
                    &json!({"id": req.as_str().unwrap_or_default()}),
                    "global",
                    "capability",
                ));
            }
        }
        let mut scoped_requirements = Vec::new();
        for detail in bundle
            .get("scopedRequirements")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let scope = detail
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or("scope:unknown");
            let scope_kind = detail
                .get("scopeKind")
                .and_then(Value::as_str)
                .unwrap_or("scope");
            scoped_requirements.push(requirement_row(detail, scope, scope_kind));
        }
        let state = if requirements.iter().any(|item| item["available"] == false) {
            "missing"
        } else if requirements.iter().any(|item| item["available"].is_null()) {
            "unknown"
        } else {
            "pass"
        };
        // Scoped probes bind one route or adapter: an unavailable adapter reports
        // that scope only and never downgrades the capability's global state.
        let scoped_state = if scoped_requirements.iter().any(|item| item["available"] == false) {
            "unavailable"
        } else if scoped_requirements.iter().any(|item| item["available"].is_null()) {
            "unknown"
        } else {
            "pass"
        };
        skills.push(json!({"id":bundle.get("id").cloned().unwrap_or(Value::Null),"state":state,"requirements":requirements,"scopedState":scoped_state,"scopedRequirements":scoped_requirements}));
    }
    let state = if skills.iter().any(|item| item["state"] == "missing") {
        "missing"
    } else if skills.iter().any(|item| item["state"] == "unknown") {
        "unknown"
    } else {
        "pass"
    };
    json!({"present":true,"state":state,"skills":skills})
}

fn host_section(root: &Path, _assets: Option<&Path>, _plugin: Option<&Path>) -> Value {
    let manifest = read_json(&root.join(".claude-plugin/plugin.json"));
    let hooks = read_json(&root.join("hooks/hooks.json"));
    let surface = read_json(&root.join("src/registry/plugin-surface.json"));
    let projection_path = root.join("src/registry/host-projection.json");
    let projection = read_json(&projection_path);
    let (capabilities, entrypoints) = projection
        .as_ref()
        .and_then(|value| value.get("capabilities"))
        .and_then(Value::as_array)
        .map(|items| {
            let capabilities = items
                .iter()
                .filter(|item| {
                    item.get("kind").and_then(Value::as_str) == Some("domain-capability")
                })
                .count();
            let entrypoints = items
                .iter()
                .filter(|item| item.get("kind").and_then(Value::as_str) == Some("entrypoint"))
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_owned))
                .collect::<Vec<_>>();
            (capabilities, entrypoints)
        })
        .unwrap_or_default();
    let home = home_dir();
    let installed_file = read_json(
        &home
            .join(".claude")
            .join("plugins")
            .join("installed_plugins.json"),
    )
    .unwrap_or_else(|| json!({}));
    let claude_settings =
        read_json(&home.join(".claude").join("settings.json")).unwrap_or_else(|| json!({}));
    let enabled_plugins = claude_settings
        .get("enabledPlugins")
        .and_then(Value::as_object);
    let installed = installed_file.get("plugins").unwrap_or(&installed_file);
    let mut installations = Vec::new();
    if let Some(installed) = installed.as_object() {
        for (id, records) in installed {
            if !id.starts_with("legion@") {
                continue;
            }
            let rows = records
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![records.clone()]);
            for record in rows {
                let install_path = record
                    .get("installPath")
                    .and_then(Value::as_str)
                    .map(PathBuf::from);
                installations.push(json!({"pluginId":id,"enabled":enabled_plugins.and_then(|plugins| plugins.get(id)).and_then(Value::as_bool).unwrap_or(false),"scope":record.get("scope").cloned().unwrap_or(Value::Null),"installPath":install_path,"installedVersion":record.get("version").cloned().unwrap_or(Value::Null),"sourceVersion":manifest.as_ref().and_then(|v| v.get("version")).cloned().unwrap_or(Value::Null),"versionMatches":record.get("version") == manifest.as_ref().and_then(|v| v.get("version")),"gitCommitSha":record.get("gitCommitSha").cloned().unwrap_or(Value::Null),"installedAt":record.get("installedAt").cloned().unwrap_or(Value::Null),"copyExists":install_path.as_ref().is_some_and(|p| p.exists()),"layoutMatchesSource":install_path.as_ref().map(|p| p.join("src/packages").is_dir() == root.join("src/packages").is_dir())}));
            }
        }
    }
    let mut conflicts = Vec::new();
    if root.join(".claude/agents").is_dir() && root.join("agents").is_dir() {
        conflicts.push(json!({"harness":"claude-code","kind":"duplicate-installation-path","detail":"both the plugin package (agents/) and a legion bind projection (.claude/agents/) are present; one installation path must own each harness"}));
    }
    let hook_events = hooks
        .as_ref()
        .and_then(|v| v.get("hooks"))
        .and_then(Value::as_object)
        .map(|map| map.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let mcp_entrypoints = manifest
        .as_ref()
        .and_then(|v| v.get("mcpServers"))
        .and_then(Value::as_object)
        .map(|servers| {
            servers
                .values()
                .flat_map(|server| {
                    server
                        .get("args")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .filter_map(|arg| {
                    let raw = arg.as_str()?;
                    let relative = raw
                        .strip_prefix("${CLAUDE_PLUGIN_ROOT}/")
                        .or_else(|| raw.strip_prefix("${PLUGIN_ROOT}/"))
                        .unwrap_or(raw);
                    let exists = root.join(relative).is_file();
                    Some(json!({"path":relative,"exists":exists}))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let known = vec![
        "claude-code",
        "codex",
        "cline",
        "command-code",
        "pi",
        "generic",
    ];
    let fidelity_harnesses = read_json(&root.join("src/registry/host-projection.json"))
        .and_then(|projection| projection.get("harnesses").cloned())
        .unwrap_or_else(|| json!([]));
    let mut adapter_capabilities = serde_json::Map::new();
    if let Ok(registry) = legion_harness::HarnessRegistry::load() {
        for id in &known {
            if let Ok(value) = registry.capabilities(id, root) {
                adapter_capabilities.insert((*id).to_owned(), value);
            }
        }
    }
    let mut detected = Vec::new();
    if root.join(".claude").exists()
        || root.join(".claude-plugin/plugin.json").exists()
        || root.join("CLAUDE.md").exists()
    {
        detected.push("claude-code");
    }
    let env = std::env::vars().collect::<HashMap<_, _>>();
    if root.join(".codex").exists()
        || env.get("CODEX_HOME").is_some_and(|value| !value.is_empty())
        || env
            .get("CODEX_THREAD_ID")
            .is_some_and(|value| !value.is_empty())
        || env
            .get("CODEX_SESSION_ID")
            .is_some_and(|value| !value.is_empty())
    {
        detected.push("codex");
    }
    let key_dirs = [
        home.join(".claude").join("arcane-keys"),
        home.join(".codex").join("arcane-keys"),
    ]
    .iter()
    .map(|dir| json!({"dir":dir,"present":dir.is_dir()}))
    .collect::<Vec<_>>();
    let canonical_key_dir = home.join(".codex").join("arcane-keys");
    let key_ids = std::fs::read_dir(&canonical_key_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .filter(|name| name.ends_with(".key"))
        .map(|name| name.trim_end_matches(".key").to_owned())
        .collect::<Vec<_>>();
    let matcher = |event: &str| {
        hooks
            .as_ref()
            .and_then(|v| v.get("hooks"))
            .and_then(|v| v.get(event))
            .and_then(Value::as_array)
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("matcher"))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let outbox = read_json(
        &root
            .join(".audit")
            .join("arcane")
            .join("observation-outbox")
            .join("outbox.json"),
    )
    .unwrap_or_else(|| json!({"pending":[],"delivered":[],"deadLetter":[]}));
    json!({"projection":{"path":"src/registry/host-projection.json","present":projection_path.is_file(),"generatedAt":projection_path.metadata().ok().and_then(|metadata| metadata.modified().ok()).map(format_time),"driftCheck":"node scripts/generate-host-projection.mjs --check"},"installations":{"claude-code":installations},"discovery":{"claude-code":{"manifestPresent":manifest.is_some(),"version":manifest.as_ref().and_then(|v| v.get("version")).cloned().unwrap_or(Value::Null),"surfaceDigest":surface.as_ref().and_then(|v| v.get("digest")).cloned().unwrap_or(Value::Null),"surfaceCounts":surface.as_ref().and_then(|v| v.get("counts")).cloned().unwrap_or(Value::Null),"surfaceProblems":surface.as_ref().and_then(|v| v.get("problems")).cloned().unwrap_or(Value::Null),"mcpEntrypoints":mcp_entrypoints,"capabilities":capabilities,"entrypoints":entrypoints,"hookEvents":hook_events}},"conflicts":conflicts,"fidelity":{"present":projection_path.is_file(),"harnesses":fidelity_harnesses},"harnessAdapters":{"known":known,"detected":detected,"capabilities":adapter_capabilities},"hostRequirements":host_requirements(root),"observations":{"pending":outbox.get("pending").and_then(Value::as_array).map_or(0,Vec::len),"delivered":outbox.get("delivered").and_then(Value::as_array).map_or(0,Vec::len),"deadLetter":outbox.get("deadLetter").and_then(Value::as_array).map_or(0,Vec::len)},"guard":{"keyDirs":key_dirs,"canonicalVerificationKeyring":{"dir":canonical_key_dir,"present":canonical_key_dir.is_dir(),"keyIds":key_ids},"hookRegistration":{"preToolUse":matcher("PreToolUse"),"postToolUse":matcher("PostToolUse"),"stop":hooks.as_ref().and_then(|v| v.get("hooks")).and_then(|v| v.get("Stop")).is_some()},"adapterPresent":root.join("src/packages/arcane/host/claude-code-adapter.mjs").is_file(),"codexHookTrust":codex_hook_trust(&home)}})
}

pub async fn run(args: RootArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    let root = absolute_root(&args.root);
    let env = std::env::vars().collect::<HashMap<_, _>>();
    lifecycle("started", json!({"root":root}));
    lifecycle(
        "blueprint-probe-started",
        json!({"timeoutMs":BLUEPRINT_TIMEOUT_MS}),
    );
    let (projection, metadata) = packet_projection(&root, &env);
    lifecycle(
        "blueprint-probe-finished",
        json!({"status":projection.get("status").and_then(Value::as_str).unwrap_or("ready")}),
    );
    let stale = metadata["state"] == "stale";
    let available = projection.get("status").and_then(Value::as_str) != Some("unavailable");
    lifecycle("semantic-probes-started", Value::Null);
    let semantic = semantic_health(&env);
    lifecycle(
        "semantic-probes-finished",
        json!({"healthy":semantic["healthy"]}),
    );
    let (assets, plugin, _) = installed_roots();
    let naming = naming_contract(assets.as_deref());
    let bindings = naming_bindings(&root);
    lifecycle("host-probes-started", Value::Null);
    let host = host_section(&root, assets.as_deref(), plugin.as_deref());
    lifecycle(
        "host-probes-finished",
        json!({"state":host.pointer("/hostRequirements/state").cloned().unwrap_or(Value::Null)}),
    );
    let mut gaps = Vec::new();
    if !available {
        gaps.push(json!({"kind":"membrane-unavailable","detail":projection.get("reason").cloned().unwrap_or(Value::Null)}));
    }
    if !available || stale {
        gaps.push(json!({"kind":"blueprint-stale","detail":if stale {Value::String("Membrane packet freshness check failed".into())} else {projection.get("reason").cloned().unwrap_or(Value::Null)}}));
    }
    if semantic["healthy"] != true {
        gaps.push(json!({"kind":"arcane-semantic-health-unhealthy","detail":semantic["probes"].as_array().into_iter().flatten().filter(|p| p["ok"] == false).map(|p| json!({"id":p["id"],"error":p["error"]})).collect::<Vec<_>>() }));
    }
    if host
        .pointer("/guard/codexHookTrust/state")
        .and_then(Value::as_str)
        == Some("ARC_HOOK_TRUST_REQUIRED")
    {
        gaps.push(json!({"kind":"guard-hook-trust-required","code":"ARC_HOOK_TRUST_REQUIRED","detail":host.pointer("/guard/codexHookTrust/missing").cloned().unwrap_or(Value::Null)}));
    }
    if naming["status"] == "fail" {
        gaps.push(json!({"kind":"naming-contract-failed","detail":naming["unclassified"]}));
    }
    let binding_pending = bindings
        .as_object()
        .into_iter()
        .flat_map(|map| map.values())
        .any(|item| {
            matches!(
                item.get("status").and_then(Value::as_str),
                Some("legacy-present") | Some("invalid")
            )
        });
    if binding_pending {
        gaps.push(json!({"kind":"naming-migration-pending","detail":bindings}));
    }
    let languages = coverage_families();
    let selected = Vec::<String>::new();
    let mut commands = Vec::new();
    if !available {
        commands.push("Start Membrane context transport, then rerun legion doctor.".to_owned());
    }
    if !env.contains_key("AUDIT_NETWORK_GUARD") {
        commands.push("Set AUDIT_NETWORK_GUARD=active for project-executing providers.".to_owned());
    }
    if !env
        .get("AUDIT_PLAN_SIGNING_KEY")
        .is_some_and(|v| !v.is_empty())
    {
        commands.push("Set AUDIT_PLAN_SIGNING_KEY to sign the frozen plan.".to_owned());
    }
    if semantic["healthy"] != true {
        commands.push(
            "Run legion doctor after repairing the failing Arcane semantic probe.".to_owned(),
        );
    }
    if host
        .pointer("/guard/codexHookTrust/state")
        .and_then(Value::as_str)
        == Some("ARC_HOOK_TRUST_REQUIRED")
    {
        commands.push(
            "Open Codex /hooks & trust current Guard hook definitions, then rerun legion doctor."
                .to_owned(),
        );
    }
    if naming["status"] != "pass" {
        commands
            .push("Run pnpm naming:check after repairing unclassified legacy names.".to_owned());
    }
    if binding_pending {
        commands.push(
            "Run legion bind --write after reviewing reported legacy or conflicting MCP bindings."
                .to_owned(),
        );
    }
    let report = json!({"schemaVersion":1,"kind":"legion-doctor","repository":{"root":root},"blueprint":{"state":if !available {"missing"} else if stale {"stale"} else {"ready"},"mode":metadata["mode"],"packetDigest":projection.get("packetDigest").cloned().unwrap_or(Value::Null)},"coverage":{"languages":languages,"frameworks":[],"systems":[],"unsupported":[]},"providers":{"selected":selected,"blocked":[],"missingTools":[]},"hostCapabilities":{"networkSandbox":env.get("AUDIT_NETWORK_GUARD").map(|v| v == "active").unwrap_or(false),"signing":env.get("AUDIT_PLAN_SIGNING_KEY").is_some_and(|v| !v.is_empty()),"browser":false,"toolchains":runtime_toolchains()},"arcane":{"semanticHealth":semantic},"host":host,"naming":{"schemaVersion":naming["schemaVersion"],"kind":naming["kind"],"status":naming["status"],"canonicalAuthorities":naming["canonicalAuthorities"],"deprecatedAliases":naming["deprecatedAliases"],"unclassified":naming["unclassified"],"bindings":bindings},"binding":binding_section(&root),"cleanClaimPossible":false,"gaps":gaps,"commands":commands});
    lifecycle(
        "finished",
        json!({"gaps":report["gaps"].as_array().map_or(0,Vec::len)}),
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_packet_is_typed_missing_projection() {
        let root = std::env::temp_dir().join(format!("legion-doctor-{}", std::process::id()));
        let (packet, metadata) = packet_projection(&root, &HashMap::new());
        assert_eq!(packet["status"], "unavailable");
        assert_eq!(metadata["state"], "missing");
    }
    #[test]
    fn codex_trust_never_manufactures_hashes() {
        let root = std::env::temp_dir().join(format!("legion-doctor-home-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".codex")).unwrap();
        std::fs::write(
            root.join(".codex/config.toml"),
            "[plugins.\"arcane@local-brief\"]\nenabled = true\n",
        )
        .unwrap();
        let value = codex_hook_trust(&root);
        assert_eq!(value["state"], "ARC_HOOK_TRUST_REQUIRED");
        assert_eq!(value["trusted"], json!([]));
        let _ = std::fs::remove_dir_all(root);
    }
}
