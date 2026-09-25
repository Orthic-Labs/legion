// Port of `src/lib/capabilities/registry.mjs`. Loading and structural
// validation of `src/registry/capabilities.json`, the canonical
// host-capability registry. Shared by `check-dependency-closure` and the
// generators packet.

use crate::checks::read_json;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

const CLASSES: &[&str] = &[
    "PACKAGE_INTERNAL",
    "HOST_CAPABILITY",
    "PROJECT_OVERLAY",
    "HISTORICAL_EVIDENCE",
];

fn capability_id_re() -> Regex {
    Regex::new(r"^[a-z][a-z0-9-]*$").unwrap()
}

fn command_re() -> Regex {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap()
}

fn invalid(path: &str, detail: &str) -> String {
    format!("{path}: {detail}")
}

fn validate_commands(value: &Value, path: &str) -> Result<(), String> {
    let arr = value
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| invalid(path, "commands must be a non-empty array"))?;
    let mut seen = std::collections::HashSet::new();
    let cmd_re = command_re();
    for command in arr {
        let s = command
            .as_str()
            .ok_or_else(|| invalid(path, &format!("invalid command {command}")))?;
        if !cmd_re.is_match(s) {
            return Err(invalid(path, &format!("invalid command {command}")));
        }
        if !seen.insert(s) {
            return Err(invalid(path, "commands contains duplicates"));
        }
    }
    Ok(())
}

fn validate_probe(probe: Option<&Value>, path: &str) -> Result<(), String> {
    let probe = match probe {
        None => return Ok(()),
        Some(v) if v.is_null() => return Ok(()),
        Some(v) => v,
    };
    if !probe.is_object() {
        return Err(invalid(path, "probe must be an object"));
    }
    let kind = probe.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let cmd_re = command_re();
    match kind {
        "command" => {
            let ok = probe
                .get("command")
                .and_then(|v| v.as_str())
                .map(|c| cmd_re.is_match(c))
                .unwrap_or(false);
            if !ok {
                return Err(invalid(path, "command probe requires a valid command"));
            }
            Ok(())
        }
        "command-any" => validate_commands(probe.get("commands").unwrap_or(&Value::Null), path),
        "env" => {
            let ok = probe
                .get("env")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if !ok {
                return Err(invalid(path, "env probe requires an env name"));
            }
            Ok(())
        }
        "path" => {
            let ok = probe
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if !ok {
                return Err(invalid(path, "path probe requires a path"));
            }
            Ok(())
        }
        other => Err(invalid(path, &format!("unknown probe kind \"{other}\""))),
    }
}

pub fn validate_capability_registry(registry: &Value, path: &str) -> Result<(), String> {
    if !registry.is_object() {
        return Err(invalid(path, "registry must be an object"));
    }
    if registry.get("schemaVersion").and_then(|v| v.as_i64()) != Some(1)
        || registry.get("kind").and_then(|v| v.as_str()) != Some("legion-capability-registry")
    {
        return Err(invalid(path, "registry has an unsupported schema"));
    }
    let classes = registry
        .get("classes")
        .filter(|v| v.is_object())
        .ok_or_else(|| invalid(path, "registry classes must be an object"))?;
    for klass in CLASSES {
        let ok = classes
            .get(*klass)
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !ok {
            return Err(invalid(path, &format!("registry does not document {klass}")));
        }
    }
    let capabilities = registry
        .get("capabilities")
        .filter(|v| v.is_object())
        .ok_or_else(|| invalid(path, "registry capabilities must be an object"))?;
    let id_re = capability_id_re();
    for (id, entry) in capabilities.as_object().unwrap() {
        let entry_path = format!("{path}#capabilities.{id}");
        if !id_re.is_match(id) {
            return Err(invalid(&entry_path, "invalid capability id"));
        }
        if !entry.is_object() {
            return Err(invalid(&entry_path, "capability must be an object"));
        }
        for field in ["kind", "summary", "degradation", "remedy"] {
            let ok = entry
                .get(field)
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if !ok {
                return Err(invalid(&entry_path, &format!("capability declares no {field}")));
            }
        }
        validate_probe(entry.get("probe"), &entry_path)?;
        if let Some(commands) = entry.get("commands") {
            if !commands.is_null() {
                validate_commands(commands, &entry_path)?;
            }
        }
    }
    Ok(())
}

pub fn load_capability_registry(package_root: &Path) -> Result<Value, String> {
    let path = package_root.join("src/registry/capabilities.json");
    if !path.is_file() {
        return Err(format!("capability registry is absent: {}", path.display()));
    }
    let registry = read_json(&path)?;
    let label = path.display().to_string();
    validate_capability_registry(&registry, &label)?;
    Ok(registry)
}

/// Map executable command aliases (lowercased) to their declared host
/// capability id.
pub fn command_capability_map(registry: &Value) -> Result<HashMap<String, String>, String> {
    let mut commands = HashMap::new();
    let empty = serde_json::Map::new();
    let capabilities = registry
        .get("capabilities")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    for (id, entry) in capabilities {
        let mut aliases: Vec<String> = entry
            .get("commands")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if let Some(probe) = entry.get("probe") {
            if probe.get("kind").and_then(|v| v.as_str()) == Some("command") {
                if let Some(c) = probe.get("command").and_then(|v| v.as_str()) {
                    aliases.push(c.to_string());
                }
            } else if probe.get("kind").and_then(|v| v.as_str()) == Some("command-any") {
                if let Some(arr) = probe.get("commands").and_then(|v| v.as_array()) {
                    for c in arr.iter().filter_map(|x| x.as_str()) {
                        aliases.push(c.to_string());
                    }
                }
            }
        }
        let mut dedup: std::collections::HashSet<String> = std::collections::HashSet::new();
        for command in aliases {
            if !dedup.insert(command.clone()) {
                continue;
            }
            let key = command.to_lowercase();
            if let Some(prior) = commands.get(&key) {
                if prior != id {
                    return Err(format!(
                        "capability registry maps command {command} to both {prior} and {id}"
                    ));
                }
            }
            commands.insert(key, id.clone());
        }
    }
    Ok(commands)
}
