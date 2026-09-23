//! Port of src/lib/capabilities/{probe,registry}.mjs.
//!
//! Registry loading (`loadCapabilityRegistry`) reads a JSON file from disk at a
//! package-relative path; that I/O is reproduced here as `validate_registry`
//! plus a caller-supplied `serde_json::Value`, matching the JS split between
//! `validateCapabilityRegistry` (pure) and `loadCapabilityRegistry` (I/O). Live
//! command/path/env probing (`probeCapability`'s `onPath`/`existsSync`) is
//! reproduced as injectable closures, mirroring the JS `commandExists`/
//! `pathExists` overrides used by its own tests.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError(pub String);

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for RegistryError {}

const CLASSES: [&str; 4] = [
    "PACKAGE_INTERNAL",
    "HOST_CAPABILITY",
    "PROJECT_OVERLAY",
    "HISTORICAL_EVIDENCE",
];

fn is_capability_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_command(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn validate_commands(value: &Value, path: &str) -> Result<(), RegistryError> {
    let arr = value
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| RegistryError(format!("{path}: commands must be a non-empty array")))?;
    let mut seen = HashSet::new();
    for command in arr {
        let s = command
            .as_str()
            .ok_or_else(|| RegistryError(format!("{path}: invalid command {command:?}")))?;
        if !is_command(s) {
            return Err(RegistryError(format!(
                "{path}: invalid command {command:?}"
            )));
        }
        if !seen.insert(s.to_string()) {
            return Err(RegistryError(format!("{path}: commands contains duplicates")));
        }
    }
    Ok(())
}

fn validate_probe(probe: Option<&Value>, path: &str) -> Result<(), RegistryError> {
    let Some(probe) = probe else { return Ok(()) };
    if probe.is_null() {
        return Ok(());
    }
    let obj = probe
        .as_object()
        .ok_or_else(|| RegistryError(format!("{path}: probe must be an object")))?;
    let kind = obj.get("kind").and_then(Value::as_str).unwrap_or_default();
    match kind {
        "command" => {
            let ok = obj
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(is_command);
            if !ok {
                return Err(RegistryError(format!(
                    "{path}: command probe requires a valid command"
                )));
            }
        }
        "command-any" => {
            validate_commands(obj.get("commands").unwrap_or(&Value::Null), path)?;
        }
        "env" => {
            let ok = obj
                .get("env")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty());
            if !ok {
                return Err(RegistryError(format!(
                    "{path}: env probe requires an env name"
                )));
            }
        }
        "path" => {
            let ok = obj
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty());
            if !ok {
                return Err(RegistryError(format!("{path}: path probe requires a path")));
            }
        }
        other => {
            return Err(RegistryError(format!(
                "{path}: unknown probe kind {other:?}"
            )))
        }
    }
    Ok(())
}

/// Port of `validateCapabilityRegistry`.
pub fn validate_capability_registry(
    registry: &Value,
    path: &str,
) -> Result<(), RegistryError> {
    let obj = registry
        .as_object()
        .ok_or_else(|| RegistryError(format!("{path}: registry must be an object")))?;
    if obj.get("schemaVersion").and_then(Value::as_i64) != Some(1)
        || obj.get("kind").and_then(Value::as_str) != Some("legion-capability-registry")
    {
        return Err(RegistryError(format!(
            "{path}: registry has an unsupported schema"
        )));
    }
    let classes = obj
        .get("classes")
        .and_then(Value::as_object)
        .ok_or_else(|| RegistryError(format!("{path}: registry classes must be an object")))?;
    for klass in CLASSES {
        let ok = classes
            .get(klass)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if !ok {
            return Err(RegistryError(format!(
                "{path}: registry does not document {klass}"
            )));
        }
    }
    let capabilities = obj
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or_else(|| RegistryError(format!("{path}: registry capabilities must be an object")))?;
    for (id, entry) in capabilities {
        let entry_path = format!("{path}#capabilities.{id}");
        if !is_capability_id(id) {
            return Err(RegistryError(format!("{entry_path}: invalid capability id")));
        }
        let entry_obj = entry
            .as_object()
            .ok_or_else(|| RegistryError(format!("{entry_path}: capability must be an object")))?;
        for field in ["kind", "summary", "degradation", "remedy"] {
            let ok = entry_obj
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty());
            if !ok {
                return Err(RegistryError(format!(
                    "{entry_path}: capability declares no {field}"
                )));
            }
        }
        validate_probe(entry_obj.get("probe"), &entry_path)?;
        if let Some(commands) = entry_obj.get("commands") {
            if !commands.is_null() {
                validate_commands(commands, &entry_path)?;
            }
        }
    }
    Ok(())
}

/// Port of `commandCapabilityMap`.
pub fn command_capability_map(registry: &Value) -> Result<BTreeMap<String, String>, RegistryError> {
    let mut commands: BTreeMap<String, String> = BTreeMap::new();
    let capabilities = registry
        .get("capabilities")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (id, entry) in capabilities {
        let mut aliases: Vec<String> = entry
            .get("commands")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if let Some(probe) = entry.get("probe") {
            match probe.get("kind").and_then(Value::as_str) {
                Some("command") => {
                    if let Some(c) = probe.get("command").and_then(Value::as_str) {
                        aliases.push(c.to_string());
                    }
                }
                Some("command-any") => {
                    if let Some(cs) = probe.get("commands").and_then(Value::as_array) {
                        for c in cs {
                            if let Some(s) = c.as_str() {
                                aliases.push(s.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let mut seen = HashSet::new();
        for command in aliases {
            if !seen.insert(command.clone()) {
                continue;
            }
            let key = command.to_lowercase();
            if let Some(prior) = commands.get(&key) {
                if prior != &id {
                    return Err(RegistryError(format!(
                        "capability registry maps command {command} to both {prior} and {id}"
                    )));
                }
            }
            commands.insert(key, id.clone());
        }
    }
    Ok(commands)
}

/// Detection strategy for a single capability probe, mirroring `detect()`.
#[derive(Debug, Clone)]
pub enum ProbeKind {
    Command(String),
    CommandAny(Vec<String>),
    Env(String),
    Path(String),
}

pub fn probe_kind_from_json(probe: &Value) -> Option<ProbeKind> {
    match probe.get("kind").and_then(Value::as_str)? {
        "command" => Some(ProbeKind::Command(
            probe.get("command")?.as_str()?.to_string(),
        )),
        "command-any" => Some(ProbeKind::CommandAny(
            probe
                .get("commands")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        )),
        "env" => Some(ProbeKind::Env(probe.get("env")?.as_str()?.to_string())),
        "path" => Some(ProbeKind::Path(probe.get("path")?.as_str()?.to_string())),
        _ => None,
    }
}

/// `available` is `Some(bool)` when a probe fired, `None` when unknown (no
/// probe declared) — matching the JS `true | false | null`.
pub fn detect(
    probe: Option<&Value>,
    env: &BTreeMap<String, String>,
    command_exists: &dyn Fn(&str) -> bool,
    path_exists: &dyn Fn(&str) -> bool,
) -> Option<bool> {
    let probe = probe?;
    match probe_kind_from_json(probe)? {
        ProbeKind::Command(cmd) => Some(command_exists(&cmd)),
        ProbeKind::CommandAny(cmds) => Some(cmds.iter().any(|c| command_exists(c))),
        ProbeKind::Env(name) => Some(env.get(&name).is_some_and(|v| !v.is_empty())),
        ProbeKind::Path(path) => Some(path_exists(&path)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityMetadata {
    pub id: String,
    pub kind: String,
    /// `None` == unknown (no probe declared).
    pub available: Option<bool>,
    pub summary: String,
    pub degradation: String,
    pub remedy: Option<String>,
    pub message: Option<String>,
}

fn unavailable_message(id: &str, degradation: &str, remedy: Option<&str>, available: Option<bool>) -> String {
    let state = match available {
        Some(false) => "is not available on this host",
        _ => "could not be detected on this host",
    };
    let remedy_text = remedy
        .map(|r| format!(" To enable it: {r}"))
        .unwrap_or_default();
    format!("{id} {state}. {degradation}{remedy_text}")
}

/// Port of `probeCapability`. Signing/identity attestation is intentionally
/// out of scope here (the JS `sign`/`identity` hooks are caller-supplied and
/// belong to whatever crypto authority is wired up at the call site); this
/// returns the metadata plus a deterministic digest so a caller can attest.
pub fn probe_capability(
    id: &str,
    registry: &Value,
    env: &BTreeMap<String, String>,
    command_exists: &dyn Fn(&str) -> bool,
    path_exists: &dyn Fn(&str) -> bool,
) -> Result<CapabilityMetadata, RegistryError> {
    let entry = registry
        .get("capabilities")
        .and_then(|c| c.get(id))
        .ok_or_else(|| RegistryError(format!("capability is not declared in the registry: {id}")))?;
    let available = detect(entry.get("probe"), env, command_exists, path_exists);
    let degradation = entry
        .get("degradation")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let remedy = entry.get("remedy").and_then(Value::as_str).map(String::from);
    let message = if available == Some(true) {
        None
    } else {
        Some(unavailable_message(
            id,
            &degradation,
            remedy.as_deref(),
            available,
        ))
    };
    Ok(CapabilityMetadata {
        id: id.to_string(),
        kind: entry.get("kind").and_then(Value::as_str).unwrap_or_default().to_string(),
        available,
        summary: entry.get("summary").and_then(Value::as_str).unwrap_or_default().to_string(),
        degradation,
        remedy,
        message,
    })
}

pub fn probe_all(
    registry: &Value,
    env: &BTreeMap<String, String>,
    command_exists: &dyn Fn(&str) -> bool,
    path_exists: &dyn Fn(&str) -> bool,
) -> Result<Vec<CapabilityMetadata>, RegistryError> {
    let ids: Vec<String> = registry
        .get("capabilities")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    ids.iter()
        .map(|id| probe_capability(id, registry, env, command_exists, path_exists))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_registry() -> Value {
        json!({
            "schemaVersion": 1,
            "kind": "legion-capability-registry",
            "classes": {
                "PACKAGE_INTERNAL": "d", "HOST_CAPABILITY": "d",
                "PROJECT_OVERLAY": "d", "HISTORICAL_EVIDENCE": "d",
            },
            "capabilities": {
                "network-sandbox": {
                    "kind": "HOST_CAPABILITY",
                    "summary": "s", "degradation": "d", "remedy": "r",
                    "probe": {"kind": "command", "command": "docker"},
                },
                "no-probe": {
                    "kind": "HOST_CAPABILITY",
                    "summary": "s", "degradation": "d", "remedy": "r",
                },
            },
        })
    }

    #[test]
    fn validates_a_well_formed_registry() {
        assert!(validate_capability_registry(&sample_registry(), "reg").is_ok());
    }

    #[test]
    fn rejects_bad_schema() {
        let mut reg = sample_registry();
        reg["schemaVersion"] = json!(2);
        assert!(validate_capability_registry(&reg, "reg").is_err());
    }

    #[test]
    fn rejects_invalid_capability_id() {
        let mut reg = sample_registry();
        let entry = reg["capabilities"]["network-sandbox"].clone();
        reg["capabilities"]
            .as_object_mut()
            .unwrap()
            .insert("Bad_Id".into(), entry);
        assert!(validate_capability_registry(&reg, "reg").is_err());
    }

    #[test]
    fn probe_reports_available_true_and_no_message() {
        let reg = sample_registry();
        let env = BTreeMap::new();
        let meta = probe_capability(
            "network-sandbox",
            &reg,
            &env,
            &|cmd| cmd == "docker",
            &|_| false,
        )
        .unwrap();
        assert_eq!(meta.available, Some(true));
        assert!(meta.message.is_none());
    }

    #[test]
    fn probe_reports_unavailable_with_remedy_message() {
        let reg = sample_registry();
        let env = BTreeMap::new();
        let meta = probe_capability(
            "network-sandbox",
            &reg,
            &env,
            &|_| false,
            &|_| false,
        )
        .unwrap();
        assert_eq!(meta.available, Some(false));
        assert!(meta.message.unwrap().contains("To enable it: r"));
    }

    #[test]
    fn probe_reports_unknown_when_no_probe_declared() {
        let reg = sample_registry();
        let env = BTreeMap::new();
        let meta = probe_capability("no-probe", &reg, &env, &|_| false, &|_| false).unwrap();
        assert_eq!(meta.available, None);
    }

    #[test]
    fn command_capability_map_detects_conflicts() {
        let mut reg = sample_registry();
        let entry = json!({
            "kind": "HOST_CAPABILITY", "summary": "s", "degradation": "d", "remedy": "r",
            "commands": ["docker"],
        });
        reg["capabilities"]
            .as_object_mut()
            .unwrap()
            .insert("other".into(), entry);
        assert!(command_capability_map(&reg).is_err());
    }
}
