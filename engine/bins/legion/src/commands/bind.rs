use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const HARNESS_NAMES: [&str; 4] = ["claude-code", "codex", "gemini", "agents-md"];

#[derive(Debug, Args)]
pub struct BindArgs {
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub check: bool,
    #[arg(long)]
    pub write: bool,
    #[arg(long)]
    pub registrations: bool,
    #[arg(long = "harness")]
    pub harness: Vec<String>,
}

pub fn run(args: BindArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(|_| {
        CommandError::usage(format!("root does not exist: {}", args.root.display()))
    })?;

    if args.registrations {
        return registrations_report(&root);
    }
    if args.check && args.write {
        return Err(CommandError::usage("bind accepts either --check or --write, not both"));
    }
    for name in &args.harness {
        if !HARNESS_NAMES.contains(&name.as_str()) {
            return Err(CommandError::usage(format!(
                "unknown harness: {name} (expected one of {})",
                HARNESS_NAMES.join("|")
            )));
        }
    }

    let dry_run = !args.write;
    let target_names = if args.harness.is_empty() {
        detect_harnesses(&root)
    } else {
        args.harness.clone()
    };

    let harnesses = target_names
        .iter()
        .map(|name| harness_preview(&root, name))
        .collect::<Vec<_>>();
    if args.write {
        return Err(CommandError::incomplete(
            "native bind --write is not connected; use legion harness install for host projections",
        ));
    }

    Ok(json!({
        "schemaVersion": 1,
        "kind": if dry_run { "legion-bind-preview" } else { "legion-bind-result" },
        "root": root,
        "harnesses": harnesses,
        "dryRun": dry_run,
    }))
}

fn registrations_report(root: &Path) -> CommandResult {
    let home = home_dir();
    let enumeration = enumerate_registrations(&home, Some(root));
    let duplicates = enumeration
        .get("duplicates")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false);
    let mut output = json!({
        "schemaVersion": 1,
        "kind": "legion-bind-registrations",
        "root": root,
        "sources": enumeration["sources"].clone(),
        "registrations": enumeration["registrations"].clone(),
        "duplicates": enumeration["duplicates"].clone(),
    });
    if duplicates {
        output["status"] = json!("policy-fail");
    }
    Ok(output)
}

fn detect_harnesses(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if gemini_detect(root) {
        names.push("gemini".into());
    }
    names
}

fn harness_preview(root: &Path, name: &str) -> Value {
    match name {
        "claude-code" => json!({
            "name": "claude-code",
            "present": root.join(".claude").exists(),
            "fidelityTier": "retired",
            "wouldWrite": [],
            "artifacts": [],
            "drift": [],
            "managedConflicts": [],
            "retired": true,
            "note": "Claude Code is installed by the Legion plugin package, not by legion bind. Use the plugin (npm run plugin:dev for the live-source dev command); bind no longer writes .claude/ for Claude Code (one installation path owns each harness).",
        }),
        "codex" => json!({
            "name": "codex",
            "present": root.join(".codex").exists(),
            "fidelityTier": "full",
            "wouldWrite": [],
            "artifacts": [],
            "drift": [],
            "managedConflicts": [],
            "quarantined": true,
            "note": "legion bind no longer auto-selects codex; the harness adapter seam installs it (legion harness install codex). This writer remains reachable only via an explicit --harness codex, for its legacy migration paths.",
        }),
        "agents-md" => json!({
            "name": "agents-md",
            "present": root.join("AGENTS.md").exists(),
            "fidelityTier": "doctrine-only",
            "wouldWrite": [],
            "artifacts": [],
            "drift": [],
            "managedConflicts": [],
            "quarantined": true,
            "note": "legion bind no longer auto-selects generic; the harness adapter seam installs it (legion harness install generic). This writer remains reachable only via an explicit --harness generic, for its legacy migration paths.",
        }),
        "gemini" => {
            let targets = gemini_targets(root);
            json!({
                "name": "gemini",
                "present": gemini_detect(root),
                "fidelityTier": "full",
                "wouldWrite": targets.iter().map(|target| json!({"path": target["path"], "reason": target["reason"]})).collect::<Vec<_>>(),
                "artifacts": [],
                "drift": [],
                "managedConflicts": [],
            })
        }
        _ => json!({
            "name": name,
            "present": false,
            "fidelityTier": "unknown",
            "wouldWrite": [],
            "artifacts": [],
            "drift": [],
            "managedConflicts": [],
        }),
    }
}

fn gemini_detect(root: &Path) -> bool {
    root.join(".gemini").exists() || root.join("GEMINI.md").exists()
}

fn gemini_targets(root: &Path) -> Vec<Value> {
    vec![
        json!({
            "path": root.join("GEMINI.md"),
            "reason": "install Legion role context for Gemini CLI",
        }),
        json!({
            "path": root.join(".gemini").join("settings.json"),
            "reason": "register Legion MCP server in Gemini project settings",
        }),
    ]
}

fn home_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        return home;
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn enumerate_registrations(home: &Path, root: Option<&Path>) -> Value {
    let mut registrations = Vec::new();
    let mut sources = Vec::new();
    settings_source(
        &home.join(".claude").join("settings.json"),
        "user-settings",
        &mut registrations,
        &mut sources,
    );
    if let Some(root) = root {
        settings_source(
            &root.join(".claude").join("settings.json"),
            "project-settings",
            &mut registrations,
            &mut sources,
        );
        settings_source(
            &root.join(".claude").join("settings.local.json"),
            "project-local-settings",
            &mut registrations,
            &mut sources,
        );
    }
    skills_dir_plugins(home, &mut registrations, &mut sources);
    marketplace_plugins(home, &mut registrations, &mut sources);

    let mut by_key: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for entry in &registrations {
        let event = entry["event"].as_str().unwrap_or_default();
        let handler = entry["handler"].as_str().unwrap_or_default();
        by_key
            .entry(format!("{event}::{handler}"))
            .or_default()
            .push(entry.clone());
    }
    let mut duplicates = Vec::new();
    for (key, entries) in by_key {
        if entries.len() <= 1 {
            continue;
        }
        let distinct_sources = entries
            .iter()
            .filter_map(|entry| entry.get("source").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        if distinct_sources.len() <= 1 {
            continue;
        }
        let mut parts = key.splitn(2, "::").collect::<Vec<_>>();
        let event = parts.first().copied().unwrap_or_default();
        let handler = parts.get(1).copied().unwrap_or_default();
        let source_list = distinct_sources.into_iter().collect::<Vec<_>>();
        duplicates.push(json!({
            "event": event,
            "handler": handler,
            "count": entries.len(),
            "sources": source_list,
            "detail": format!(
                "{} runs {}x on {} (from {})",
                handler,
                entries.len(),
                event,
                source_list.join(" + ")
            ),
        }));
    }
    registrations.sort_by(|left, right| {
        format!(
            "{}{}{}",
            left["event"].as_str().unwrap_or_default(),
            left["handler"].as_str().unwrap_or_default(),
            left["source"].as_str().unwrap_or_default()
        )
        .cmp(&format!(
            "{}{}{}",
            right["event"].as_str().unwrap_or_default(),
            right["handler"].as_str().unwrap_or_default(),
            right["source"].as_str().unwrap_or_default()
        ))
    });
    duplicates.sort_by(|left, right| {
        left["detail"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["detail"].as_str().unwrap_or_default())
    });
    json!({
        "sources": sources,
        "registrations": registrations,
        "duplicates": duplicates,
    })
}

fn settings_source(path: &Path, source: &str, registrations: &mut Vec<Value>, sources: &mut Vec<Value>) {
    if !path.is_file() {
        return;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    sources.push(json!({
        "source": source,
        "path": path,
        "kind": "settings",
    }));
    from_hooks_object(value.get("hooks"), source, path, registrations);
}

fn from_hooks_object(hooks: Option<&Value>, source: &str, source_path: &Path, out: &mut Vec<Value>) {
    let Some(hooks) = hooks.and_then(Value::as_object) else {
        return;
    };
    for (event, rows) in hooks {
        let Some(rows) = rows.as_array() else {
            continue;
        };
        for row in rows {
            let Some(nested) = row.get("hooks").and_then(Value::as_array) else {
                continue;
            };
            for hook in nested {
                let command = hook.get("command").and_then(Value::as_str);
                let args = hook
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                out.push(json!({
                    "event": event,
                    "handler": handler_id(command, &args),
                    "source": source,
                    "sourcePath": source_path,
                }));
            }
        }
    }
}

fn plugin_source(dir: &Path, source: &str, registrations: &mut Vec<Value>, sources: &mut Vec<Value>) {
    let manifest = dir.join(".claude-plugin").join("plugin.json");
    let hooks_file = dir.join("hooks").join("hooks.json");
    if !manifest.is_file() || !hooks_file.is_file() {
        return;
    }
    let Ok(bytes) = std::fs::read(&hooks_file) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    sources.push(json!({
        "source": source,
        "path": hooks_file,
        "kind": "plugin",
    }));
    if value.get("hooks").is_some() {
        from_hooks_object(value.get("hooks"), source, &hooks_file, registrations);
    } else {
        from_hooks_object(Some(&value), source, &hooks_file, registrations);
    }
}

fn skills_dir_plugins(home: &Path, registrations: &mut Vec<Value>, sources: &mut Vec<Value>) {
    let skills = home.join(".claude").join("skills");
    if !skills.exists() {
        return;
    }
    let real = std::fs::canonicalize(&skills).unwrap_or(skills);
    let entries = std::fs::read_dir(&real);
    let Ok(entries) = entries else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        plugin_source(
            &entry.path(),
            &format!("plugin:{name}@skills-dir"),
            registrations,
            sources,
        );
    }
}

fn marketplace_plugins(home: &Path, registrations: &mut Vec<Value>, sources: &mut Vec<Value>) {
    let installed_path = home.join(".claude").join("plugins").join("installed_plugins.json");
    let Ok(bytes) = std::fs::read(&installed_path) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    let plugins = value
        .get("plugins")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (name, rows) in plugins {
        let Some(rows) = rows.as_array() else {
            continue;
        };
        for row in rows {
            let Some(install_path) = row.get("installPath").and_then(Value::as_str) else {
                continue;
            };
            plugin_source(
                Path::new(install_path),
                &format!("plugin:{name}"),
                registrations,
                sources,
            );
        }
    }
}

fn handler_id(command: Option<&str>, args: &[&str]) -> String {
    let text = command.unwrap_or_default().replace('\\', "/");
    if text.contains("rhook") || text.contains("rhook.exe") {
        return format!("rhook {}", args.join(" ")).trim().to_owned();
    }
    if text.contains("legion-hook") || text.contains("legion-hook.exe") {
        return "legion-hook".into();
    }
    for token in text.split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'') {
        if token.ends_with(".py")
            || token.ends_with(".mjs")
            || token.ends_with(".cjs")
            || token.ends_with(".js")
        {
            return Path::new(token)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(token)
                .to_owned();
        }
    }
    text.chars().take(60).collect::<String>().trim().to_owned()
}
