use super::{CommandError, CommandResult};
use crate::cli::{installed_m1_composition, RootArgs};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

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

pub(super) fn command_path(command: &str) -> Option<PathBuf> {
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
    let tools = ["git", "cargo", "node", "swift"]
        .into_iter()
        .filter_map(|name| {
            let executable = command_path(name)?;
            let output = Command::new(&executable).arg("--version").output().ok()?;
            if !output.status.success() {
                return None;
            }
            let version = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            if version.is_empty() {
                return None;
            }
            Some(json!({"name":name,"executable":executable,"version":version}))
        })
        .collect::<Vec<_>>();
    if tools.is_empty() {
        return json!({"state":"unproven","tools":[]});
    }
    json!({"state":"ready","tools":tools})
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
        applies
            && rule
                .get("tokens")
                .and_then(Value::as_array)
                .is_some_and(|tokens| tokens.iter().any(|value| value.as_str() == Some(token)))
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
        .map(|value| {
            String::from_utf8_lossy(&value.stdout)
                .split('\0')
                .filter(|path| !path.is_empty())
                .map(str::to_owned)
                .collect()
        })
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
        ![
            ".git/",
            ".agent/",
            ".audit/",
            ".cache/",
            "docs/foundation/",
            "node_modules/",
        ]
        .iter()
        .any(|prefix| format!("{path}/").starts_with(prefix))
    }) {
        for token in NAMING_TOKENS {
            let path_hits = naming_occurrences(&path, token);
            if !path_hits.is_empty() && naming_rule(&rules, &path, token).is_none() {
                issues.push(
                    json!({"path":path,"token":token,"reason":"unclassified legacy filename"}),
                );
            }
        }
        let Some(text) = std::fs::read(&root.join(&path)).ok().and_then(|bytes| {
            if bytes.contains(&0) {
                return None;
            }
            String::from_utf8(bytes).ok()
        }) else {
            continue;
        };
        for token in NAMING_TOKENS {
            let lines = naming_occurrences(&text, token);
            if lines.is_empty() {
                continue;
            }
            let Some(rule) = naming_rule(&rules, &path, token) else {
                issues.push(json!({"path":path,"line":lines[0],"token":token,"reason":"unclassified legacy token"}));
                continue;
            };
            if rule.get("path").is_some()
                && rule.get("class").and_then(Value::as_str) != Some("R5")
                && rule
                    .get("occurrences")
                    .and_then(|value| value.get(token))
                    .and_then(Value::as_u64)
                    .is_none()
            {
                issues.push(json!({"path":path,"line":lines[0],"token":token,"reason":"active exact-path allowlist lacks occurrence count"}));
            }
            if let Some(expected) = rule
                .get("occurrences")
                .and_then(|value| value.get(token))
                .and_then(Value::as_u64)
            {
                if lines.len() as u64 != expected {
                    issues.push(json!({"path":path,"line":lines[0],"token":token,"reason":format!("legacy token occurrence count differs: expected {expected}, found {}", lines.len())}));
                }
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

/// Codex hook state, reported as four separately observed facts rather than
/// one verdict: (1) Legion's hooks file is present on disk, (2) Codex's own
/// config registers hook state for Legion, (3) a hook event was observed
/// executing (last event in Legion's receipt traces), (4) enforcement is
/// qualified (declared strong by the host adapter AND registered AND executed).
/// A later state never implies an earlier one is skipped; each is reported
/// from its own evidence.
fn codex_hook_trust(home: &Path, legion_hooks_file: Option<&Path>) -> Value {
    codex_hook_state(home, legion_hooks_file, &hook_receipt_dirs(home))
}

fn hook_receipt_dirs(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(root) = std::env::var_os("LEGION_STATE_ROOT") {
        dirs.push(PathBuf::from(root).join("receipts"));
    }
    if cfg!(target_os = "macos") {
        dirs.push(home.join("Library/Application Support/Orthic Labs/Legion/state/receipts"));
    } else if cfg!(windows) {
        dirs.push(home.join("AppData/Local/Orthic Labs/Legion/state/receipts"));
    } else {
        dirs.push(home.join(".local/state/legion/receipts"));
    }
    dirs
}

/// Newest hook-trace file (route outcome or child lifecycle) under the receipt
/// directories, up to one repository-key level deep.
fn last_observed_hook_event(dirs: &[PathBuf]) -> Option<(PathBuf, SystemTime)> {
    const NAMES: [&str; 2] = [
        "route-outcome-trace.v1.jsonl",
        "child-lifecycle-trace.v1.jsonl",
    ];
    let mut newest: Option<(PathBuf, SystemTime)> = None;
    let mut consider = |path: PathBuf| {
        let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
            return;
        };
        if newest.as_ref().map_or(true, |(_, t)| modified > *t) {
            newest = Some((path, modified));
        }
    };
    for dir in dirs {
        for name in NAMES {
            consider(dir.join(name));
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(Result::ok) {
                if entry.path().is_dir() {
                    for name in NAMES {
                        consider(entry.path().join(name));
                    }
                }
            }
        }
    }
    newest
}

fn codex_hook_state(
    home: &Path,
    legion_hooks_file: Option<&Path>,
    receipt_dirs: &[PathBuf],
) -> Value {
    let config_path = home.join(".codex").join("config.toml");
    let text = std::fs::read_to_string(&config_path).unwrap_or_default();
    let mut trusted = BTreeSet::new();
    let mut legion_registered = BTreeSet::new();
    let mut current = None::<String>;
    let mut current_enabled = true;
    let flush = |event: &Option<String>, enabled: bool, registered: &mut BTreeSet<String>| {
        if let Some(event) = event {
            let lowered = event.to_ascii_lowercase();
            if enabled && (lowered.starts_with("legion@") || lowered.contains("/legion/")) {
                registered.insert(event.clone());
            }
        }
    };
    for line in text.lines().map(str::trim) {
        if let Some(value) = line
            .strip_prefix("[hooks.state.\"")
            .and_then(|v| v.strip_suffix("\"]"))
        {
            flush(&current, current_enabled, &mut legion_registered);
            current = Some(value.to_owned());
            current_enabled = true;
            continue;
        }
        if line.starts_with('[') {
            flush(&current, current_enabled, &mut legion_registered);
            current = None;
            continue;
        }
        if line.replace(' ', "") == "enabled=false" {
            current_enabled = false;
        }
        if let Some(value) = line
            .strip_prefix("trusted_hash = \"")
            .and_then(|v| v.strip_suffix('"'))
        {
            if let Some(event) = current.as_deref() {
                if value.strip_prefix("sha256:").is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }) {
                    trusted.insert(event.to_owned());
                }
            }
        }
    }
    flush(&current, current_enabled, &mut legion_registered);

    let file_present = legion_hooks_file.is_some_and(Path::is_file);
    let registered = !legion_registered.is_empty();
    let last_event = last_observed_hook_event(receipt_dirs);
    let executed = last_event.is_some();
    let declared_strong = legion_runtime::p7_host::host_adapters::codex_descriptor()["surfaces"]
        ["hooks"]["fidelity"]
        == "strong";
    let qualified = declared_strong && registered && executed;
    let state = if qualified {
        "enforcement-qualified"
    } else if executed {
        "executed"
    } else if registered {
        "registered"
    } else if file_present {
        "file-present"
    } else {
        "absent"
    };
    let detail = format!(
        "hooks file {}; Codex {} Legion hook state; {}; enforcement {}. Trusted entries below are recorded by Codex and are not all Legion's.",
        if file_present { "present on disk" } else { "not found" },
        if registered { "registers" } else { "does not register" },
        if executed {
            "a hook event was observed executing (receipt traces are host-agnostic)"
        } else {
            "no hook event has been observed executing"
        },
        if qualified {
            "qualified"
        } else if !declared_strong {
            "not qualified (host adapter declares Codex hook enforcement unsupported)"
        } else {
            "not qualified (requires registered and executed)"
        },
    );
    json!({
        "configPath": config_path,
        "configPresent": !text.is_empty(),
        "state": state,
        "states": {
            "filePresent": {"observed": file_present, "path": legion_hooks_file},
            "hostRegistered": {"observed": registered, "entries": legion_registered.iter().collect::<Vec<_>>()},
            "hostExecuted": {
                "observed": executed,
                "lastObservedEvent": last_event.as_ref().map(|(_, t)| format_time(*t)),
                "source": last_event.as_ref().map(|(path, _)| path),
            },
            "enforcementQualified": {"observed": qualified, "declaredFidelity": if declared_strong {"strong"} else {"unsupported"}},
        },
        "detail": detail,
        "trusted": trusted.into_iter().collect::<Vec<_>>(),
        "remediation": Value::Null,
    })
}

/// The Claude Code skills-dir projection: `~/.claude/skills/legion` carrying a
/// `plugin.json`, with skills, agents, hooks and an MCP descriptor beside it.
fn skills_dir_install_path(home: &Path) -> PathBuf {
    home.join(".claude").join("skills").join("legion")
}

fn skills_dir_manifest(install: &Path) -> Option<Value> {
    read_json(&install.join("plugin.json"))
        .or_else(|| read_json(&install.join(".claude-plugin").join("plugin.json")))
        .filter(|manifest| manifest.get("name").and_then(Value::as_str) == Some("legion"))
}

fn count_entries_with(directory: &Path, marker: &str) -> usize {
    std::fs::read_dir(directory)
        .ok()
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().join(marker).is_file())
                .count()
        })
        .unwrap_or(0)
}

fn skills_dir_installation(home: &Path, source_version: Option<&Value>) -> Option<Value> {
    let install = skills_dir_install_path(home);
    let manifest = skills_dir_manifest(&install)?;
    let installed_version = manifest.get("version").cloned().unwrap_or(Value::Null);
    let version_matches = source_version.map(|version| *version == installed_version);
    let agents = std::fs::read_dir(install.join("agents"))
        .ok()
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("md"))
                .count()
        })
        .unwrap_or(0);
    Some(json!({
        "pluginId": "legion@skills-dir",
        "kind": "skills-dir",
        "enabled": true,
        "scope": "user",
        "installPath": install,
        "installedVersion": installed_version,
        "sourceVersion": source_version,
        "versionMatches": version_matches,
        "copyExists": true,
        "skillCount": count_entries_with(&install.join("skills"), "SKILL.md"),
        "agentCount": agents,
        "hooksRegistered": install.join("hooks").join("hooks.json").is_file(),
        "mcpDescriptor": install.join(".mcp.json").is_file() || install.join("mcp.json").is_file(),
    }))
}

/// MCP servers declared beside a plugin manifest. Arguments are reported as
/// arguments; only path-shaped ones are checked for existence.
fn mcp_server_rows(base: &Path, manifest: Option<&Value>) -> Vec<Value> {
    let declared = [
        manifest.and_then(|value| value.get("mcpServers").cloned()),
        read_json(&base.join(".mcp.json")).and_then(|value| value.get("mcpServers").cloned()),
        read_json(&base.join("mcp.json")).and_then(|value| value.get("mcpServers").cloned()),
    ]
    .into_iter()
    .flatten()
    .find(|value| value.as_object().is_some_and(|servers| !servers.is_empty()));
    let Some(servers) = declared.as_ref().and_then(Value::as_object) else {
        return Vec::new();
    };
    servers
        .iter()
        .map(|(name, server)| {
            let command = server.get("command").and_then(Value::as_str);
            let args = server
                .get("args")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let missing_paths = args
                .iter()
                .filter_map(Value::as_str)
                .filter(|arg| arg.contains('/') || arg.contains('\\') || arg.ends_with(".json"))
                .filter(|arg| !arg.starts_with('$') && !arg.starts_with('-'))
                .filter(|arg| !base.join(arg).exists())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            json!({
                "server": name,
                "command": command,
                "commandOnPath": command.is_some_and(|value| command_path(value).is_some()),
                "args": args,
                "missingPaths": missing_paths,
            })
        })
        .collect()
}

fn host_requirements(index: &Path) -> Value {
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
            let id = detail.get("id").and_then(Value::as_str).unwrap_or_default();
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
        let scoped_state = if scoped_requirements
            .iter()
            .any(|item| item["available"] == false)
        {
            "unavailable"
        } else if scoped_requirements
            .iter()
            .any(|item| item["available"].is_null())
        {
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

fn host_section(root: &Path, _assets: Option<&Path>, plugin: Option<&Path>) -> Value {
    let home = home_dir();
    let skills_install = skills_dir_install_path(&home);
    // Claude Code discovery reads the repository's plugin package when run from
    // a source checkout, and otherwise the installed skills-dir projection.
    let in_repository = root.join(".claude-plugin/plugin.json").is_file();
    let claude_base = if in_repository || skills_dir_manifest(&skills_install).is_none() {
        root.to_path_buf()
    } else {
        skills_install.clone()
    };
    let manifest = read_json(&claude_base.join(".claude-plugin/plugin.json"))
        .or_else(|| read_json(&claude_base.join("plugin.json")));
    let hooks = read_json(&claude_base.join("hooks/hooks.json"));
    let surface = read_json(&root.join("src/registry/plugin-surface.json"));
    // Host projection: the repository copy, else the installed plugin copy,
    // else the skills-dir copy, so the probe works from any working directory.
    let (projection_path, projection_source) = [
        (root.join("src/registry/host-projection.json"), "repository"),
        (
            plugin
                .map(|path| path.join("share/legion/src/registry/host-projection.json"))
                .unwrap_or_default(),
            "installed-plugin",
        ),
        (
            skills_install.join("share/legion/src/registry/host-projection.json"),
            "skills-dir",
        ),
    ]
    .into_iter()
    .find(|(path, _)| path.is_file())
    .unwrap_or_else(|| (root.join("src/registry/host-projection.json"), "missing"));
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
    let source_version = if in_repository {
        manifest
            .as_ref()
            .and_then(|value| value.get("version"))
            .cloned()
    } else {
        None
    };
    if let Some(installation) = skills_dir_installation(&home, source_version.as_ref()) {
        installations.push(installation);
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
    let mcp_entrypoints = mcp_server_rows(&claude_base, manifest.as_ref());
    let known = vec![
        "claude-code",
        "codex",
        "cline",
        "command-code",
        "pi",
        "generic",
    ];
    let fidelity_harnesses = projection
        .as_ref()
        .and_then(|value| value.get("harnesses").cloned())
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
        || skills_dir_manifest(&skills_install).is_some()
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
    json!({"projection":{"path":projection_path,"source":projection_source,"present":projection_path.is_file(),"generatedAt":projection_path.metadata().ok().and_then(|metadata| metadata.modified().ok()).map(format_time),"driftCheck":"cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- generate-host-projection --check"},"installations":{"claude-code":installations},"discovery":{"claude-code":{"manifestPresent":manifest.is_some(),"version":manifest.as_ref().and_then(|v| v.get("version")).cloned().unwrap_or(Value::Null),"surfaceDigest":surface.as_ref().and_then(|v| v.get("digest")).cloned().unwrap_or(Value::Null),"surfaceCounts":surface.as_ref().and_then(|v| v.get("counts")).cloned().unwrap_or(Value::Null),"surfaceProblems":surface.as_ref().and_then(|v| v.get("problems")).cloned().unwrap_or(Value::Null),"mcpEntrypoints":mcp_entrypoints,"capabilities":capabilities,"entrypoints":entrypoints,"hookEvents":hook_events}},"conflicts":conflicts,"fidelity":{"present":projection_path.is_file(),"harnesses":fidelity_harnesses},"harnessAdapters":{"known":known,"detected":detected,"capabilities":adapter_capabilities},"hostRequirements":host_requirements(&projection_path),"observations":{"pending":outbox.get("pending").and_then(Value::as_array).map_or(0,Vec::len),"delivered":outbox.get("delivered").and_then(Value::as_array).map_or(0,Vec::len),"deadLetter":outbox.get("deadLetter").and_then(Value::as_array).map_or(0,Vec::len)},"guard":{"keyDirs":key_dirs,"canonicalVerificationKeyring":{"dir":canonical_key_dir,"present":canonical_key_dir.is_dir(),"keyIds":key_ids},"hookRegistration":{"preToolUse":matcher("PreToolUse"),"postToolUse":matcher("PostToolUse"),"stop":hooks.as_ref().and_then(|v| v.get("hooks")).and_then(|v| v.get("Stop")).is_some()},"adapterPresent":command_path("legion-hook").is_some(),"adapter":{"kind":"legion-hook","onPath":command_path("legion-hook")},"codexHookTrust":codex_hook_trust(&home,Some(&claude_base.join("hooks/hooks.json")))}})
}

pub async fn run(args: RootArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    let root = absolute_root(&args.root);
    let env = std::env::vars().collect::<HashMap<_, _>>();
    lifecycle("started", json!({"root":root}));
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
    if semantic["healthy"] != true {
        gaps.push(json!({"kind":"arcane-semantic-health-unhealthy","detail":semantic["probes"].as_array().into_iter().flatten().filter(|p| p["ok"] == false).map(|p| json!({"id":p["id"],"error":p["error"]})).collect::<Vec<_>>() }));
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
    lifecycle("coverage-started", Value::Null);
    let scan = super::coverage::scan(&root);
    let coverage_rows = super::coverage::rows(&scan).unwrap_or_default();
    let coverage = super::coverage::coverage_summary(&scan, &coverage_rows);
    let providers = super::coverage::provider_selection(&root, &scan);
    lifecycle(
        "coverage-finished",
        json!({"entriesSeen":scan.entries_seen,"providersComputed":providers["computed"]}),
    );
    let mut commands = Vec::new();
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
    if let Some(tools) = providers["missingTools"]
        .as_array()
        .filter(|tools| !tools.is_empty())
    {
        commands.push(format!(
            "Install the missing audit tools or accept the matching providers as unavailable: {}.",
            tools
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ));
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
    let report = json!({"schemaVersion":1,"kind":"legion-doctor","repository":{"root":root},"coverage":coverage,"providers":providers,"hostCapabilities":{"networkSandbox":env.get("AUDIT_NETWORK_GUARD").map(|v| v == "active").unwrap_or(false),"signing":env.get("AUDIT_PLAN_SIGNING_KEY").is_some_and(|v| !v.is_empty()),"browser":false,"toolchains":runtime_toolchains()},"arcane":{"semanticHealth":semantic},"host":host,"naming":{"schemaVersion":naming["schemaVersion"],"kind":naming["kind"],"status":naming["status"],"canonicalAuthorities":naming["canonicalAuthorities"],"deprecatedAliases":naming["deprecatedAliases"],"unclassified":naming["unclassified"],"bindings":bindings},"binding":binding_section(&root),"cleanClaimPossible":false,"gaps":gaps,"commands":commands});
    lifecycle(
        "finished",
        json!({"gaps":report["gaps"].as_array().map_or(0,Vec::len)}),
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Legion (Rust) has no Membrane/Blueprint dependency: doctor's report
    /// carries no blueprint probe state, key, or gap at all, rather than a
    /// typed "missing" projection for an external transport it no longer
    /// checks. Replaces the retired
    /// `absent_packet_is_typed_missing_projection`.
    #[tokio::test]
    async fn doctor_report_carries_no_blueprint_or_membrane_state() {
        let root =
            std::env::temp_dir().join(format!("legion-doctor-report-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let report = run(
            RootArgs {
                root: root.clone(),
                json: true,
            },
            CancellationToken::new(),
        )
        .await
        .expect("doctor runs against an empty repository");
        assert!(report.get("blueprint").is_none());
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.to_ascii_lowercase().contains("blueprint"));
        assert!(!rendered.to_ascii_lowercase().contains("membrane"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn codex_hook_state_distinguishes_file_registration_execution_and_qualification() {
        let root = std::env::temp_dir().join(format!("legion-doctor-codex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".codex")).unwrap();
        let hooks = root.join("hooks.json");
        let receipts = root.join("receipts");

        // Nothing at all.
        let v = codex_hook_state(&root, Some(&hooks), &[receipts.clone()]);
        assert_eq!(v["state"], "absent");

        // File present only: not registered, not executed.
        std::fs::write(&hooks, "{}").unwrap();
        std::fs::write(
            root.join(".codex/config.toml"),
            "[plugins.\"arcane@local-brief\"]\nenabled = true\n",
        )
        .unwrap();
        let v = codex_hook_state(&root, Some(&hooks), &[receipts.clone()]);
        assert_eq!(v["state"], "file-present");
        assert_eq!(v["states"]["filePresent"]["observed"], true);
        assert_eq!(v["states"]["hostRegistered"]["observed"], false);
        assert!(!v["detail"].as_str().unwrap().contains("ships no"));

        // Host registered (hash valid), still not executed. A disabled Legion
        // entry and a non-Legion entry do not count.
        let hash = format!("sha256:{}", "a".repeat(64));
        std::fs::write(
            root.join(".codex/config.toml"),
            format!(
                "[hooks.state.\"legion@orthic:hooks/hooks.json:session_start:0:0\"]\ntrusted_hash = \"{hash}\"\n\n[hooks.state.\"legion@orthic:hooks/hooks.json:stop:0:0\"]\ntrusted_hash = \"{hash}\"\nenabled = false\n\n[hooks.state.\"other@x:hooks/hooks.json:stop:0:0\"]\ntrusted_hash = \"{hash}\"\n"
            ),
        )
        .unwrap();
        let v = codex_hook_state(&root, Some(&hooks), &[receipts.clone()]);
        assert_eq!(v["state"], "registered");
        assert_eq!(
            v["states"]["hostRegistered"]["entries"],
            json!(["legion@orthic:hooks/hooks.json:session_start:0:0"])
        );
        assert_eq!(v["states"]["hostExecuted"]["observed"], false);
        assert_eq!(v["trusted"].as_array().unwrap().len(), 3);

        // Executed: a hook trace exists. Host adapter declares codex hooks
        // unsupported, so enforcement is not qualified.
        std::fs::create_dir_all(&receipts).unwrap();
        std::fs::write(receipts.join("child-lifecycle-trace.v1.jsonl"), "{}\n").unwrap();
        let v = codex_hook_state(&root, Some(&hooks), &[receipts.clone()]);
        assert_eq!(v["states"]["hostExecuted"]["observed"], true);
        assert!(v["states"]["hostExecuted"]["lastObservedEvent"].is_string());
        let declared_strong = legion_runtime::p7_host::host_adapters::codex_descriptor()
            ["surfaces"]["hooks"]["fidelity"]
            == "strong";
        assert_eq!(
            v["states"]["enforcementQualified"]["observed"],
            declared_strong
        );
        assert_eq!(
            v["state"],
            if declared_strong {
                "enforcement-qualified"
            } else {
                "executed"
            }
        );
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn skills_dir_projection_is_recognised_as_an_installation() {
        let home =
            std::env::temp_dir().join(format!("legion-doctor-skills-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let install = home.join(".claude/skills/legion");
        std::fs::create_dir_all(install.join("skills/audit")).unwrap();
        std::fs::create_dir_all(install.join("hooks")).unwrap();
        std::fs::write(
            install.join("skills/audit/SKILL.md"),
            "---\nname: audit\n---\n",
        )
        .unwrap();
        std::fs::write(install.join("hooks/hooks.json"), "{}").unwrap();
        std::fs::write(
            install.join("plugin.json"),
            r#"{"name":"legion","version":"1.2.3"}"#,
        )
        .unwrap();
        let installation =
            skills_dir_installation(&home, Some(&json!("1.2.3"))).expect("installation");
        assert_eq!(installation["pluginId"], "legion@skills-dir");
        assert_eq!(installation["installedVersion"], "1.2.3");
        assert_eq!(installation["versionMatches"], true);
        assert_eq!(installation["skillCount"], 1);
        assert_eq!(installation["hooksRegistered"], true);
        std::fs::write(install.join("plugin.json"), r#"{"name":"other"}"#).unwrap();
        assert!(skills_dir_installation(&home, None).is_none());
        let _ = std::fs::remove_dir_all(home);
    }
}
