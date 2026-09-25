//! Rust port of `node_modules/@rightkit/ax/plugin/portable-core.mjs`.
//!
//! Faithful port of `assemblePortableCore` / `validatePortableCore` /
//! `validateResourceClosure` / `normalizeClientProjections`, used by
//! `scripts/assemble-native-release.mjs` (ported in `assemble_native_release.rs`).
//! `@rightkit/ax` is an external npm package; this module ports the behaviour
//! it performs so assembly needs no Node.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{json, Value};

pub const PORTABLE_CORE_SCHEMA_VERSION: i64 = 1;
pub const PORTABLE_CORE_KIND: &str = "rightax-portable-core";

/// Mirrors `CLIENT_PROJECTION_KINDS` exactly (insertion order preserved via a
/// Vec of (name, object) pairs so JSON output key order matches).
pub fn client_projection_kinds() -> Vec<(&'static str, Value)> {
    vec![
        (
            "claude",
            json!({
                "portableCore": false,
                "projection": "claude-native-plugin+standalone-skills",
                "fidelity": "full+skills-only",
                "executableRegistration": true
            }),
        ),
        (
            "codex",
            json!({
                "portableCore": true,
                "projection": "agent-plugins+codex-sidecar",
                "fidelity": "full+sidecar",
                "executableRegistration": true
            }),
        ),
        (
            "cursor",
            json!({
                "portableCore": true,
                "projection": "agent-plugins+optional-cursor-sidecar",
                "fidelity": "full+optional-sidecar",
                "executableRegistration": true
            }),
        ),
        (
            "pi",
            json!({
                "portableCore": false,
                "projection": "agents-skills",
                "fidelity": "skills-only",
                "executableRegistration": false
            }),
        ),
        (
            "antigravity",
            json!({
                "portableCore": false,
                "projection": "antigravity-native-plugin",
                "fidelity": "native",
                "schema": "https://antigravity.google/schemas/v1/plugin.json",
                "executableRegistration": true
            }),
        ),
    ]
}

fn private_path_re() -> Regex {
    Regex::new(r"(?i)(?:^|[\\/])(?:\.env(?:\..*)?|private|personal|secrets?|credentials?|workspace-private)(?:$|[.\\/])").unwrap()
}
fn private_extension_re() -> Regex {
    Regex::new(r"(?i)\.(?:pem|p12|pfx|key|kdbx|sqlite3?)$").unwrap()
}
fn personal_marker_re() -> Regex {
    Regex::new(r"(?i)(?:C:\\Users\\adrds|D:\\Claude|/Users/adrds|<private-overlay>|workspace-private)").unwrap()
}
fn sensitive_key_re() -> Regex {
    Regex::new(r"(?i)^(?:password|passwd|secret|secrets|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|credentials)$").unwrap()
}
fn skill_id_re() -> Regex {
    Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap()
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: &'static str,
    pub message: String,
}
fn finding(message: impl Into<String>) -> Finding {
    Finding { rule_id: "portable-core", severity: "error", message: message.into() }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn assert_contained(root: &Path, path: &Path, label: &str) -> Result<PathBuf, String> {
    let base = root.canonicalize().map_err(|e| format!("{label}: {e}"))?;
    let candidate = path.canonicalize().map_err(|e| format!("{label}: {e}"))?;
    if !candidate.starts_with(&base) {
        return Err(format!("{label} escapes source root"));
    }
    Ok(candidate)
}

fn assert_skill_id(id: &str) -> Result<(), String> {
    if !skill_id_re().is_match(id) {
        return Err(format!("invalid public skill ID: {id}"));
    }
    Ok(())
}

fn assert_regular_public_file(path: &Path, label: &str) -> Result<(), String> {
    let path_str = path.to_string_lossy();
    if private_path_re().is_match(&path_str) {
        return Err(format!("portable core rejects private/personal path: {path_str}"));
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if private_extension_re().is_match(name) {
            return Err(format!("portable core rejects private/personal path: {path_str}"));
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("portable core requires regular non-symlink {label}: {path_str}"));
    }
    Ok(())
}

fn scan_public_value(value: &Value, location: &str, findings: &mut Vec<Finding>) {
    match value {
        Value::String(s) => {
            if personal_marker_re().is_match(s) {
                findings.push(finding(format!("{location} contains private/personal workspace content")));
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                scan_public_value(item, &format!("{location}[{i}]"), findings);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                if sensitive_key_re().is_match(key) {
                    findings.push(finding(format!("{location}.{key} is a secret-bearing manifest field")));
                }
                if (key.eq_ignore_ascii_case("private") || key.eq_ignore_ascii_case("personal"))
                    && item.as_bool() != Some(false)
                {
                    findings.push(finding(format!("{location}.{key} must be false or absent")));
                }
                scan_public_value(item, &format!("{location}.{key}"), findings);
            }
        }
        _ => {}
    }
}

/// Copies a tree, rejecting symlinks/private paths, returning forward-slash
/// relative output paths. Mirrors `copyTreeNoLinks`.
fn copy_tree_no_links(source: &Path, destination: &Path, prefix: &str, files: &mut Vec<String>) -> Result<(), String> {
    let entries = fs::read_dir(source).map_err(|e| format!("{}: {e}", source.display()))?;
    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let from = source.join(&name);
        let to = destination.join(&name);
        let output_path = if prefix.is_empty() { name_str.clone() } else { format!("{prefix}/{name_str}") };
        let from_str = from.to_string_lossy();
        if private_path_re().is_match(&from_str) || private_extension_re().is_match(&name_str) {
            return Err(format!("portable core rejects private/personal path: {from_str}"));
        }
        let meta = fs::symlink_metadata(&from).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("portable core cannot contain symlink: {from_str}"));
        }
        if meta.is_dir() {
            fs::create_dir_all(&to).map_err(|e| e.to_string())?;
            copy_tree_no_links(&from, &to, &output_path, files)?;
        } else if meta.is_file() {
            let bytes = fs::read(&from).map_err(|e| e.to_string())?;
            if !bytes.contains(&0u8) {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    if personal_marker_re().is_match(text) {
                        return Err(format!("portable core rejects personal workspace marker: {from_str}"));
                    }
                }
            }
            fs::copy(&from, &to).map_err(|e| e.to_string())?;
            files.push(output_path.replace('\\', "/"));
        } else {
            return Err(format!("portable core cannot contain special file: {from_str}"));
        }
    }
    Ok(())
}

fn enumerate_files(root: &Path, prefix: &str, files: &mut Vec<String>, findings: &mut Vec<Finding>) {
    if !root.exists() {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else { return };
    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let absolute = root.join(&name);
        let output_path = if prefix.is_empty() { name_str.clone() } else { format!("{prefix}/{name_str}") };
        if private_path_re().is_match(&output_path) || private_extension_re().is_match(&name_str) {
            findings.push(finding(format!("private/personal output file: {output_path}")));
        }
        let Ok(meta) = fs::symlink_metadata(&absolute) else { continue };
        if meta.file_type().is_symlink() {
            findings.push(finding(format!("output contains symlink: {output_path}")));
        } else if meta.is_dir() {
            enumerate_files(&absolute, &output_path, files, findings);
        } else if meta.is_file() {
            files.push(output_path.replace('\\', "/"));
            if let Ok(bytes) = fs::read(&absolute) {
                if !bytes.contains(&0u8) {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        if personal_marker_re().is_match(text) {
                            findings.push(finding(format!("personal workspace marker in output file: {output_path}")));
                        }
                    }
                }
            }
        } else {
            findings.push(finding(format!("output contains special file: {output_path}")));
        }
    }
}

fn url_scheme_re() -> Regex {
    Regex::new(r"(?i)^(?:[a-z][a-z0-9+.-]*:|//)").unwrap()
}

fn normalize_target(target: &str) -> Option<String> {
    let trimmed = target.trim();
    let trimmed = trimmed.strip_prefix('<').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix('>').unwrap_or(trimmed);
    let value = trimmed.split(['?', '#']).next().unwrap_or("");
    if value.is_empty() || value.starts_with('#') || url_scheme_re().is_match(value) {
        return None;
    }
    // Best-effort URI decode (percent-decoding); fall back to raw on failure.
    Some(percent_decode(value))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn markdown_targets(text: &str) -> Vec<String> {
    // Mirrors: /!?\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+['"][^'"]*['"])?\s*\)/g
    let re = Regex::new(r#"!?\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+['"][^'"]*['"])?\s*\)"#).unwrap();
    let mut targets = Vec::new();
    for cap in re.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            if let Some(t) = normalize_target(m.as_str()) {
                targets.push(t);
            }
        }
    }
    targets
}

pub fn validate_resource_closure(output_dir: &Path, public_files: Option<&HashSet<String>>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut enumerated_files = Vec::new();
    let mut enumerate_findings = Vec::new();
    enumerate_files(output_dir, "", &mut enumerated_files, &mut enumerate_findings);
    let allowed: HashSet<String> = match public_files {
        Some(pf) => pf.clone(),
        None => enumerated_files.iter().cloned().collect(),
    };
    let root = output_dir.canonicalize().unwrap_or_else(|_| output_dir.to_path_buf());
    for file in enumerated_files.iter().filter(|name| name.to_lowercase().ends_with(".md")) {
        let file_path: PathBuf = output_dir.join(file.split('/').collect::<PathBuf>());
        let Ok(text) = fs::read_to_string(&file_path) else { continue };
        for target in markdown_targets(&text) {
            let base_dir = file_path.parent().unwrap_or(output_dir);
            let absolute = normalize_path(&base_dir.join(&target));
            let rel = pathdiff(&root, &absolute);
            match rel {
                None => findings.push(finding(format!("{file} references resource outside portable core: {target}"))),
                Some(rel) if rel == ".." || rel.starts_with("../") => {
                    findings.push(finding(format!("{file} references resource outside portable core: {target}")))
                }
                Some(rel) => {
                    if !absolute.exists() {
                        findings.push(finding(format!("{file} references missing resource: {target}")));
                    } else if !allowed.contains(&rel) {
                        findings.push(finding(format!("{file} references undeclared resource: {rel}")));
                    }
                }
            }
        }
    }
    findings
}

/// Lexical `..`/`.` resolution without requiring existence (mirrors Node's
/// `path.resolve` semantics used before `relative`).
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        use std::path::Component::*;
        match component {
            ParentDir => {
                out.pop();
            }
            CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Forward-slash relative path from `root` to `target`, or None if it escapes
/// (used where JS computes `relative(root, x)` then checks for `..`).
fn pathdiff(root: &Path, target: &Path) -> Option<String> {
    let root = normalize_path(root);
    let target = normalize_path(target);
    let rel = target.strip_prefix(&root).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

fn validate_mcp_closure(mcp: &Value, output_dir: &Path, public_files: &HashSet<String>, findings: &mut Vec<Finding>) {
    let Some(servers) = mcp.get("mcpServers").and_then(|v| v.as_object()) else { return };
    let root = output_dir.canonicalize().unwrap_or_else(|_| output_dir.to_path_buf());
    for (name, server) in servers {
        let mut values: Vec<(String, String)> = Vec::new();
        if let Some(s) = server.get("command").and_then(|v| v.as_str()) {
            values.push(("command".to_string(), s.to_string()));
        }
        if let Some(s) = server.get("cwd").and_then(|v| v.as_str()) {
            values.push(("cwd".to_string(), s.to_string()));
        }
        if let Some(args) = server.get("args").and_then(|v| v.as_array()) {
            for (i, v) in args.iter().enumerate() {
                if let Some(s) = v.as_str() {
                    values.push((format!("args[{i}]"), s.to_string()));
                }
            }
        }
        if let Some(env) = server.get("env").and_then(|v| v.as_object()) {
            for (k, v) in env {
                if let Some(s) = v.as_str() {
                    values.push((format!("env.{k}"), s.to_string()));
                }
            }
        }
        let re = Regex::new(r"^(?:\./|\$\{PLUGIN_ROOT\}/)(.+)$").unwrap();
        for (field, value) in values {
            let Some(caps) = re.captures(&value) else { continue };
            let rel = caps[1].replace('\\', "/");
            let candidate = normalize_path(&root.join(&rel));
            match pathdiff(&root, &candidate) {
                None => findings.push(finding(format!("mcpServers.{name}.{field} escapes portable core"))),
                Some(root_rel) if root_rel == ".." || root_rel.starts_with("../") => {
                    findings.push(finding(format!("mcpServers.{name}.{field} escapes portable core")))
                }
                Some(root_rel) => {
                    if !candidate.exists() {
                        findings.push(finding(format!("mcpServers.{name}.{field} references missing resource: {rel}")));
                    } else if !public_files.contains(&root_rel) {
                        findings.push(finding(format!(
                            "mcpServers.{name}.{field} references undeclared resource: {root_rel}"
                        )));
                    }
                }
            }
        }
    }
}

pub fn normalize_client_projections(supplied: &Value) -> Result<Value, String> {
    let expected = client_projection_kinds();
    let supplied_obj = supplied.as_object().cloned().unwrap_or_default();
    for (client, _) in &expected {
        if !supplied_obj.contains_key(*client) {
            return Err(format!("missing required client projection: {client}"));
        }
    }
    let mut result = serde_json::Map::new();
    for (client, declaration) in &supplied_obj {
        let Some((_, expected_decl)) = expected.iter().find(|(c, _)| c == client) else {
            return Err(format!("unsupported client projection: {client}"));
        };
        let expected_map = expected_decl.as_object().unwrap();
        let decl_map = declaration.as_object();
        let invalid = decl_map.is_none()
            || decl_map.unwrap().keys().any(|k| !expected_map.contains_key(k))
            || expected_map.iter().any(|(k, v)| decl_map.unwrap().get(k) != Some(v));
        if invalid {
            return Err(format!("invalid {client} client projection declaration"));
        }
        if client == "pi" {
            let exec_reg = declaration.get("executableRegistration").and_then(|v| v.as_bool()).unwrap_or(false);
            let fidelity = declaration.get("fidelity").and_then(|v| v.as_str());
            if exec_reg || fidelity != Some("skills-only") {
                return Err("Pi projection cannot register executables or expose non-skill content".to_string());
            }
        }
        result.insert(client.clone(), expected_decl.clone());
    }
    Ok(Value::Object(result))
}

pub struct SkillInput {
    pub id: String,
    pub source_root: PathBuf,
    pub source_dir: PathBuf,
}

pub struct AgentInput {
    pub name: String,
    pub source_root: PathBuf,
    pub source_file: PathBuf,
}

fn normalize_agents(agents: &[AgentInput]) -> Result<Vec<(String, PathBuf)>, String> {
    let name_re = skill_id_re();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for agent in agents {
        if !name_re.is_match(&agent.name) {
            return Err(format!("invalid public agent name: {}", agent.name));
        }
        if !seen.insert(agent.name.clone()) {
            return Err(format!("duplicate public agent: {}", agent.name));
        }
        let source = assert_contained(&agent.source_root, &agent.source_file, &format!("agent {}", agent.name))?;
        assert_regular_public_file(&source, &format!("agent {}", agent.name))?;
        out.push((agent.name.clone(), source));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

pub struct AssembleParams<'a> {
    pub output_dir: &'a Path,
    pub plugin_manifest_path: &'a Path,
    pub mcp_manifest_path: Option<&'a Path>,
    pub hooks_manifest_path: Option<&'a Path>,
    pub skills: Vec<SkillInput>,
    pub agents: Vec<AgentInput>,
    pub client_projections: Value,
}

/// Rust port of `assemblePortableCore`. Returns the written contract JSON.
pub fn assemble_portable_core(params: AssembleParams) -> Result<Value, String> {
    assert_regular_public_file(params.plugin_manifest_path, "plugin manifest")?;
    let plugin = read_json(params.plugin_manifest_path)?;
    let mut manifest_findings = Vec::new();
    scan_public_value(&plugin, "plugin.json", &mut manifest_findings);
    if let Some(f) = manifest_findings.first() {
        return Err(f.message.clone());
    }

    let mut mcp: Option<Value> = None;
    if let Some(mcp_path) = params.mcp_manifest_path {
        assert_regular_public_file(mcp_path, "MCP manifest")?;
        let value = read_json(mcp_path)?;
        let mut findings = Vec::new();
        scan_public_value(&value, "mcp.json", &mut findings);
        if let Some(f) = findings.first() {
            return Err(f.message.clone());
        }
        mcp = Some(value);
    }

    let plugin_name = plugin.get("name").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty());
    let Some(plugin_name) = plugin_name else {
        return Err("plugin.json requires name".to_string());
    };
    if params.skills.is_empty() {
        return Err("portable core requires explicit public skills".to_string());
    }

    let mut seen = HashSet::new();
    let mut normalized_skills: Vec<(String, PathBuf)> = Vec::new();
    for skill in &params.skills {
        assert_skill_id(&skill.id)?;
        if !seen.insert(skill.id.clone()) {
            return Err(format!("duplicate public skill ID: {}", skill.id));
        }
        let source = assert_contained(&skill.source_root, &skill.source_dir, &format!("skill {}", skill.id))?;
        if !source.join("SKILL.md").exists() {
            return Err(format!("skill {} lacks SKILL.md", skill.id));
        }
        normalized_skills.push((skill.id.clone(), source));
    }
    normalized_skills.sort_by(|a, b| a.0.cmp(&b.0));

    let projections = normalize_client_projections(&params.client_projections)?;

    let _ = fs::remove_dir_all(params.output_dir);
    fs::create_dir_all(params.output_dir.join("skills")).map_err(|e| e.to_string())?;
    fs::copy(params.plugin_manifest_path, params.output_dir.join("plugin.json")).map_err(|e| e.to_string())?;
    let mut public_files: Vec<String> = vec!["plugin.json".to_string()];

    if let Some(mcp_path) = params.mcp_manifest_path {
        fs::copy(mcp_path, params.output_dir.join("mcp.json")).map_err(|e| e.to_string())?;
        public_files.push("mcp.json".to_string());
        let claude_plugin_dir = params.output_dir.join(".claude-plugin");
        fs::create_dir_all(&claude_plugin_dir).map_err(|e| e.to_string())?;
        fs::copy(params.plugin_manifest_path, claude_plugin_dir.join("plugin.json")).map_err(|e| e.to_string())?;
        fs::copy(mcp_path, params.output_dir.join(".mcp.json")).map_err(|e| e.to_string())?;
        fs::copy(mcp_path, params.output_dir.join("mcp_config.json")).map_err(|e| e.to_string())?;
        public_files.push(".claude-plugin/plugin.json".to_string());
        public_files.push(".mcp.json".to_string());
        public_files.push("mcp_config.json".to_string());
    }

    if let Some(hooks_path) = params.hooks_manifest_path {
        assert_regular_public_file(hooks_path, "hooks manifest")?;
        let hooks = read_json(hooks_path)?;
        let mut findings = Vec::new();
        scan_public_value(&hooks, "hooks/hooks.json", &mut findings);
        if let Some(f) = findings.first() {
            return Err(f.message.clone());
        }
        let hooks_dir = params.output_dir.join("hooks");
        fs::create_dir_all(&hooks_dir).map_err(|e| e.to_string())?;
        fs::copy(hooks_path, hooks_dir.join("hooks.json")).map_err(|e| e.to_string())?;
        public_files.push("hooks/hooks.json".to_string());
    }

    for (id, source) in &normalized_skills {
        let destination = params.output_dir.join("skills").join(id);
        fs::create_dir_all(&destination).map_err(|e| e.to_string())?;
        let mut files = Vec::new();
        copy_tree_no_links(source, &destination, &format!("skills/{id}"), &mut files)?;
        public_files.extend(files);
    }

    let normalized_agents = normalize_agents(&params.agents)?;
    if !normalized_agents.is_empty() {
        let agents_dir = params.output_dir.join("agents");
        fs::create_dir_all(&agents_dir).map_err(|e| e.to_string())?;
        for (name, source) in &normalized_agents {
            let relative = format!("agents/{name}.md");
            fs::copy(source, params.output_dir.join(&relative)).map_err(|e| e.to_string())?;
            public_files.push(relative);
        }
    }

    let public_file_set: HashSet<String> = public_files.iter().cloned().collect();
    let contract = json!({
        "schemaVersion": PORTABLE_CORE_SCHEMA_VERSION,
        "kind": PORTABLE_CORE_KIND,
        "plugin": plugin_name,
        "publicSkills": normalized_skills.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>(),
        "publicAgents": normalized_agents.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>(),
        "publicFiles": public_files,
        "privateWorkspaceContent": false,
        "clientProjections": projections,
    });
    fs::write(
        params.output_dir.join("rightax-portable-core.json"),
        format!("{}\n", serde_json::to_string_pretty(&contract).unwrap()),
    )
    .map_err(|e| e.to_string())?;

    let mut closure = validate_resource_closure(params.output_dir, Some(&public_file_set));
    if let Some(mcp_value) = &mcp {
        validate_mcp_closure(mcp_value, params.output_dir, &public_file_set, &mut closure);
    }
    let mut output_files = Vec::new();
    let mut output_findings = Vec::new();
    enumerate_files(params.output_dir, "", &mut output_files, &mut output_findings);
    let unexpected: Vec<String> = output_files
        .into_iter()
        .filter(|path| path != "rightax-portable-core.json" && !public_file_set.contains(path))
        .collect();

    if !closure.is_empty() || !output_findings.is_empty() || !unexpected.is_empty() {
        if let Some(f) = closure.first() {
            return Err(f.message.clone());
        }
        if let Some(f) = output_findings.first() {
            return Err(f.message.clone());
        }
        let path = &unexpected[0];
        return Err(format!("undeclared output file: {path}"));
    }

    Ok(contract)
}

#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn validate_portable_core_contract(contract: &Value) -> ValidationResult {
    let mut findings = Vec::new();
    if !contract.is_object() {
        findings.push(finding("portable core contract must be an object"));
    } else {
        let sv_ok = contract.get("schemaVersion").and_then(|v| v.as_i64()) == Some(PORTABLE_CORE_SCHEMA_VERSION);
        let kind_ok = contract.get("kind").and_then(|v| v.as_str()) == Some(PORTABLE_CORE_KIND);
        if !sv_ok || !kind_ok {
            findings.push(finding("invalid portable core contract identity"));
        }
        if contract.get("plugin").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).is_none() {
            findings.push(finding("portable core contract requires plugin name"));
        }
        let public_skills_ok = contract
            .get("publicSkills")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if !public_skills_ok {
            findings.push(finding("portable core contract requires publicSkills"));
        }
        let public_files_ok = contract
            .get("publicFiles")
            .and_then(|v| v.as_array())
            .map(|a| a.len() >= 2)
            .unwrap_or(false);
        if !public_files_ok {
            findings.push(finding("portable core contract requires publicFiles"));
        }
        if contract.get("privateWorkspaceContent").and_then(|v| v.as_bool()) != Some(false) {
            findings.push(finding("portable core must exclude private workspace content"));
        }
        if let Err(msg) = normalize_client_projections(contract.get("clientProjections").unwrap_or(&Value::Null)) {
            findings.push(finding(msg));
        }
    }
    ValidationResult {
        valid: findings.is_empty(),
        errors: findings.into_iter().map(|f| f.message).collect(),
    }
}

pub fn validate_portable_core(output_dir: &Path) -> ValidationResult {
    let contract_path = output_dir.join("rightax-portable-core.json");
    let mut findings = Vec::new();
    if !output_dir.join("plugin.json").exists() || !contract_path.exists() {
        findings.push(finding("portable core metadata or plugin.json missing"));
        return ValidationResult { valid: false, errors: findings.into_iter().map(|f| f.message).collect() };
    }

    let contract = read_json(&contract_path);
    let plugin = read_json(&output_dir.join("plugin.json"));
    let mut contract_value = Value::Null;
    match &contract {
        Ok(v) => contract_value = v.clone(),
        Err(e) => findings.push(finding(format!("portable core metadata parse failure: {e}"))),
    }
    let mut plugin_value = Value::Null;
    match &plugin {
        Ok(v) => plugin_value = v.clone(),
        Err(e) => findings.push(finding(format!("plugin.json parse failure: {e}"))),
    }

    let contract_result = validate_portable_core_contract(&contract_value);
    findings.extend(contract_result.errors.into_iter().map(finding));
    scan_public_value(&plugin_value, "plugin.json", &mut findings);

    if output_dir.join("mcp.json").exists() {
        match read_json(&output_dir.join("mcp.json")) {
            Ok(mcp_value) => {
                scan_public_value(&mcp_value, "mcp.json", &mut findings);
                let public_files: HashSet<String> = contract_value
                    .get("publicFiles")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                validate_mcp_closure(&mcp_value, output_dir, &public_files, &mut findings);
            }
            Err(e) => findings.push(finding(format!("mcp.json parse failure: {e}"))),
        }
    }

    let mut disk_files = Vec::new();
    let mut disk_findings = Vec::new();
    enumerate_files(output_dir, "", &mut disk_files, &mut disk_findings);
    findings.extend(disk_findings);
    let public_files: HashSet<String> = contract_value
        .get("publicFiles")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    for path in &disk_files {
        if path != "rightax-portable-core.json" && !public_files.contains(path) {
            findings.push(finding(format!("undeclared output file: {path}")));
        }
    }
    let disk_skills: BTreeSet<String> = disk_files
        .iter()
        .filter(|p| p.starts_with("skills/") && p.ends_with("/SKILL.md"))
        .filter_map(|p| p.split('/').nth(1).map(|s| s.to_string()))
        .collect();
    let contract_skills: BTreeSet<String> = contract_value
        .get("publicSkills")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if disk_skills != contract_skills {
        findings.push(finding("public skill set differs from portable core contract"));
    }
    findings.extend(validate_resource_closure(output_dir, Some(&public_files)));

    ValidationResult {
        valid: findings.is_empty(),
        errors: findings.into_iter().map(|f| f.message).collect(),
    }
}
