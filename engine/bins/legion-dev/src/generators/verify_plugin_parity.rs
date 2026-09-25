//! Port of `scripts/verify-plugin-parity.mjs`.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const SURFACE_FILE: &str = "src/registry/plugin-surface.json";
const DISTRIBUTION_CONTRACT: &str = "release/distribution-contract.json";
const CHANNELS_FILE: &str = "packaging/channels.json";
const ACTIVATION_PREFLIGHT: &str = "node scripts/verify-plugin-parity.mjs --check";

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn plugin_rel(reference: &str) -> String {
    reference.replace("${CLAUDE_PLUGIN_ROOT}/", "")
}

fn bare_command(command: Option<&str>) -> Option<String> {
    let value = command?.trim();
    let ok = !value.is_empty()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| (b as char).is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    if ok { Some(value.to_string()) } else { None }
}

fn executable_on_path(command: &str) -> Option<String> {
    let path_value = std::env::var("PATH").unwrap_or_default();
    let entries: Vec<&str> = path_value.split(if cfg!(windows) { ';' } else { ':' }).collect();
    let extensions: Vec<String> = if cfg!(windows) {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        std::iter::once(String::new()).chain(pathext.split(';').filter(|s| !s.is_empty()).map(String::from)).collect()
    } else {
        vec![String::new()]
    };
    let mut seen = BTreeSet::new();
    let candidates: Vec<String> = extensions.into_iter().map(|ext| format!("{command}{ext}")).filter(|c| seen.insert(c.clone())).collect();

    let cwd = std::env::current_dir().unwrap_or_default();
    for entry in entries {
        for candidate in &candidates {
            let base = if entry.is_empty() { cwd.clone() } else { std::path::PathBuf::from(entry) };
            let path = base.join(candidate);
            if let Ok(meta) = fs::metadata(&path) {
                if meta.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if meta.permissions().mode() & 0o111 != 0 {
                            return Some(path.display().to_string());
                        }
                    }
                    #[cfg(windows)]
                    {
                        return Some(path.display().to_string());
                    }
                }
            }
        }
    }
    None
}

/// Faithful port of `activeBootstrap(root)`.
pub fn active_bootstrap(root: &Path) -> Option<String> {
    let contract = read_json(&root.join(DISTRIBUTION_CONTRACT)).ok();
    let channels = read_json(&root.join(CHANNELS_FILE)).ok();

    let native_release = contract.as_ref().and_then(|c| c.get("nativeRelease"));
    let direct_channel = channels.as_ref().and_then(|c| c.get("channels")).and_then(|c| c.get("direct-bootstrap"));

    if native_release.and_then(|n| n.get("status")).and_then(Value::as_str) != Some("available")
        || direct_channel.and_then(|d| d.get("status")).and_then(Value::as_str) != Some("available")
    {
        return None;
    }

    let contract_url = native_release.and_then(|n| n.get("bootstrapAuthority")).and_then(Value::as_str);
    let channel_url = channels.as_ref().and_then(|c| c.get("bootstrap")).and_then(|b| b.get("stableUrl")).and_then(Value::as_str);
    let direct_url = direct_channel.and_then(|d| d.get("stableUrl")).and_then(Value::as_str);

    match contract_url {
        Some(c) if Some(c) == channel_url && Some(c) == direct_url => Some(c.to_string()),
        _ => None,
    }
}

fn declared_path_binaries(manifest: &Value, hooks: &Value) -> Vec<(String, Vec<String>)> {
    let mut order: Vec<String> = Vec::new();
    let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut add = |command: Option<&str>, source: String| {
        if let Some(binary) = bare_command(command) {
            if !map.contains_key(&binary) {
                order.push(binary.clone());
            }
            map.entry(binary).or_default().push(source);
        }
    };
    if let Some(servers) = manifest.get("mcpServers").and_then(Value::as_object) {
        for (id, server) in servers {
            add(server.get("command").and_then(Value::as_str), format!(".claude-plugin/plugin.json mcpServers.{id}"));
        }
    }
    if let Some(events) = hooks.get("hooks").and_then(Value::as_object) {
        for (event, entries) in events {
            for entry in entries.as_array().into_iter().flatten() {
                for (index, hook) in entry.get("hooks").and_then(Value::as_array).into_iter().flatten().enumerate() {
                    add(hook.get("command").and_then(Value::as_str), format!("hooks/hooks.json {event}[{index}]"));
                }
            }
        }
    }
    order.into_iter().map(|b| { let s = map.remove(&b).unwrap_or_default(); (b, s) }).collect()
}

pub struct PathBinaryReport {
    pub problems: Vec<String>,
}

pub fn check_path_binaries(root: &Path, manifest: &Value, hooks: &Value) -> PathBinaryReport {
    let bootstrap = active_bootstrap(root);
    let mut problems = Vec::new();
    for (binary, sources) in declared_path_binaries(manifest, hooks) {
        let resolved = executable_on_path(&binary);
        if resolved.is_none() && bootstrap.is_none() {
            let bootstrap_note = format!("Install via the published direct bootstrap, then rerun '{ACTIVATION_PREFLIGHT}'.");
            problems.push(format!(
                "plugin binary '{binary}' is not reachable on PATH (required by {}). {bootstrap_note}",
                sources.join(", ")
            ));
        }
    }
    PathBinaryReport { problems }
}

pub struct Surface {
    pub version: Value,
    pub skills: Vec<String>,
    pub agents: Vec<Value>,
    pub mcp_servers: Vec<Value>,
    pub hook_events: Vec<String>,
    pub hook_targets: Vec<String>,
    pub problems: Vec<String>,
}

pub fn collect_surface(root: &Path, check_installed_binaries: bool) -> Result<Surface, String> {
    let mut problems = Vec::new();

    let skills_dir = root.join("skills");
    let mut skills: Vec<String> = fs::read_dir(&skills_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|id| skills_dir.join(id).join("SKILL.md").is_file())
        .collect();
    skills.sort();

    let agents_dir = root.join("agents");
    let mut agents = Vec::new();
    if agents_dir.is_dir() {
        let mut files: Vec<String> = fs::read_dir(&agents_dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|f| f.ends_with(".md"))
            .collect();
        files.sort();
        for f in files {
            let text = fs::read_to_string(agents_dir.join(&f)).map_err(|e| e.to_string())?;
            let name = text
                .lines()
                .find_map(|l| l.strip_prefix("name:").map(|v| v.trim().to_string()))
                .filter(|s| !s.is_empty());
            if name.is_none() {
                problems.push(format!("agent {f} has no frontmatter name"));
            }
            let mut o = Map::new();
            o.insert("file".into(), Value::from(format!("agents/{f}")));
            o.insert("name".into(), name.map(Value::from).unwrap_or(Value::Null));
            agents.push(Value::Object(o));
        }
    }

    let manifest = read_json(&root.join(".claude-plugin/plugin.json"))?;
    let mut mcp_servers = Vec::new();
    if let Some(servers) = manifest.get("mcpServers").and_then(Value::as_object) {
        for (id, server) in servers {
            let args: Vec<Value> = server.get("args").and_then(Value::as_array).cloned().unwrap_or_default();
            let native = server.get("command").and_then(Value::as_str) == Some("legion")
                && args == vec![Value::from("serve"), Value::from("--stdio")];
            let entry = args
                .iter()
                .filter_map(Value::as_str)
                .map(plugin_rel)
                .find(|a| a.ends_with(".mjs") || a.ends_with(".js"));
            if !native && entry.is_none() {
                problems.push(format!("mcp server {id} declares neither installed native Legion nor a resolvable entry point"));
            } else if let Some(e) = &entry {
                if !root.join(e).exists() {
                    problems.push(format!("mcp server {id} entry point missing: {e}"));
                }
            }
            let mut o = Map::new();
            o.insert("id".into(), Value::from(id.clone()));
            o.insert("command".into(), server.get("command").cloned().unwrap_or(Value::Null));
            o.insert("args".into(), Value::Array(args));
            o.insert("entry".into(), entry.map(Value::from).unwrap_or(Value::Null));
            mcp_servers.push(Value::Object(o));
        }
    }

    let hooks = read_json(&root.join("hooks/hooks.json"))?;
    let mut hook_events: Vec<String> = hooks.get("hooks").and_then(Value::as_object).map(|o| o.keys().cloned().collect()).unwrap_or_default();
    hook_events.sort();
    let mut hook_targets: BTreeSet<String> = BTreeSet::new();
    if let Some(events) = hooks.get("hooks").and_then(Value::as_object) {
        for entries in events.values() {
            for entry in entries.as_array().into_iter().flatten() {
                for hook in entry.get("hooks").and_then(Value::as_array).into_iter().flatten() {
                    if let Some(cmd) = hook.get("command").and_then(Value::as_str) {
                        if let Some(idx) = cmd.find("${CLAUDE_PLUGIN_ROOT}/") {
                            let rest = &cmd[idx + "${CLAUDE_PLUGIN_ROOT}/".len()..];
                            let target: String = rest.chars().take_while(|c| !c.is_whitespace() && *c != '"').collect();
                            if !target.is_empty() {
                                hook_targets.insert(target);
                            }
                        }
                    }
                }
            }
        }
    }
    for target in &hook_targets {
        if !root.join(target).exists() {
            problems.push(format!("hook command target missing: {target}"));
        }
    }

    if check_installed_binaries {
        problems.extend(check_path_binaries(root, &manifest, &hooks).problems);
    }

    Ok(Surface {
        version: manifest.get("version").cloned().unwrap_or(Value::Null),
        skills,
        agents,
        mcp_servers,
        hook_events,
        hook_targets: hook_targets.into_iter().collect(),
        problems,
    })
}

/// Faithful port of `surfaceDigest(surface)`. `JSON.stringify` (default,
/// no whitespace) is matched by `serde_json::to_string` (compact).
pub fn surface_digest(surface: &Surface) -> String {
    let agent_names: Vec<Value> = surface.agents.iter().map(|a| a.get("name").cloned().unwrap_or(Value::Null)).collect();
    let mcp_shape: Vec<Value> = surface
        .mcp_servers
        .iter()
        .map(|s| {
            json!({
                "id": s.get("id"),
                "command": s.get("command"),
                "args": s.get("args"),
                "entry": s.get("entry"),
            })
        })
        .collect();
    let shape = json!({
        "skills": surface.skills,
        "agents": agent_names,
        "mcpServers": mcp_shape,
        "hooks": { "events": surface.hook_events, "targets": surface.hook_targets },
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_string(&shape).unwrap().as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn build_surface_record(root: &Path, check_installed_binaries: bool) -> Result<Value, String> {
    let surface = collect_surface(root, check_installed_binaries)?;
    let digest = surface_digest(&surface);
    let mut counts = Map::new();
    counts.insert("skills".into(), Value::from(surface.skills.len()));
    counts.insert("agents".into(), Value::from(surface.agents.len()));
    counts.insert("mcpServers".into(), Value::from(surface.mcp_servers.len()));
    counts.insert("hookEvents".into(), Value::from(surface.hook_events.len()));

    let mut hooks_out = Map::new();
    hooks_out.insert("events".into(), Value::Array(surface.hook_events.iter().cloned().map(Value::from).collect()));
    hooks_out.insert("targets".into(), Value::Array(surface.hook_targets.iter().cloned().map(Value::from).collect()));

    let mut surface_out = Map::new();
    surface_out.insert("skills".into(), Value::Array(surface.skills.iter().cloned().map(Value::from).collect()));
    surface_out.insert("agents".into(), Value::Array(surface.agents.clone()));
    surface_out.insert("mcpServers".into(), Value::Array(surface.mcp_servers.clone()));
    surface_out.insert("hooks".into(), Value::Object(hooks_out));

    let mut record = Map::new();
    record.insert("schemaVersion".into(), Value::from(1));
    record.insert("kind".into(), Value::from("legion-plugin-surface"));
    record.insert("version".into(), surface.version.clone());
    record.insert("digest".into(), Value::from(digest));
    record.insert("counts".into(), Value::Object(counts));
    record.insert("surface".into(), Value::Object(surface_out));
    record.insert("problems".into(), Value::Array(surface.problems.iter().cloned().map(Value::from).collect()));
    Ok(Value::Object(record))
}

pub fn run(root: &Path, check: bool) -> bool {
    run_opts(root, check, false)
}

pub fn run_opts(root: &Path, check: bool, structural_only: bool) -> bool {
    let record = match build_surface_record(root, !structural_only) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("verify-plugin-parity: {e}");
            return false;
        }
    };
    let problems = record.get("problems").and_then(Value::as_array).cloned().unwrap_or_default();
    let target = root.join(SURFACE_FILE);
    let rendered = format!("{}\n", serde_json::to_string_pretty(&record).unwrap());

    if !problems.is_empty() {
        let lines: Vec<String> = problems.iter().filter_map(|p| p.as_str().map(String::from)).collect();
        eprintln!("plugin surface does not resolve:\n  - {}", lines.join("\n  - "));
        return false;
    }

    if check {
        let current: Option<Value> = fs::read_to_string(&target).ok().and_then(|s| serde_json::from_str(&s).ok());
        let current = match current {
            Some(c) => c,
            None => {
                eprintln!("missing {SURFACE_FILE}; run: node scripts/verify-plugin-parity.mjs");
                return false;
            }
        };
        let current_digest = current.get("digest").and_then(Value::as_str).unwrap_or_default();
        let record_digest = record.get("digest").and_then(Value::as_str).unwrap_or_default();
        let current_version = current.get("version").cloned().unwrap_or(Value::Null);
        let record_version = record.get("version").cloned().unwrap_or(Value::Null);
        if current_digest != record_digest && current_version == record_version {
            eprintln!(
                "plugin surface changed but version did not.\n  recorded {current_digest} @ {current_version}\n  current  {record_digest} @ {record_version}\nBump the version in .claude-plugin/plugin.json (and package.json), then rerun."
            );
            return false;
        }
        if current != record {
            eprintln!("{SURFACE_FILE} is stale; run: node scripts/verify-plugin-parity.mjs");
            return false;
        }
        let counts = &record["counts"];
        println!(
            "plugin surface: resolves, {} skills / {} agents / {} mcp / {} hook events, digest {}…",
            counts["skills"], counts["agents"], counts["mcpServers"], counts["hookEvents"],
            &record_digest.chars().take(19).collect::<String>()
        );
        return true;
    }

    if let Err(e) = fs::write(&target, &rendered) {
        eprintln!("verify-plugin-parity: {e}");
        return false;
    }
    let counts = &record["counts"];
    println!(
        "wrote {SURFACE_FILE}: {} skills, {} agents, {} mcp, {} hook events",
        counts["skills"], counts["agents"], counts["mcpServers"], counts["hookEvents"]
    );
    true
}
