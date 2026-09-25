// Port of `scripts/check-dependency-closure.mjs` + `src/lib/skills/dependency-closure.mjs`.
// Every packaged semantic bundle owns one typed dependency declaration that
// classifies package resources, host capabilities, project overlays, and
// historical evidence before a host projects or invokes that bundle.

use super::{read_json, read_text};
use crate::shared::capabilities::{command_capability_map, load_capability_registry};
use crate::shared::route_resources::scoped_host_capabilities;
use crate::shared::skill_frontmatter::parse_skill_frontmatter;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const DEPENDENCY_DECLARATION: &str = "dependencies.json";
const DEPENDENCY_CLASSES: &[&str] = &[
    "PACKAGE_INTERNAL",
    "HOST_CAPABILITY",
    "PROJECT_OVERLAY",
    "HISTORICAL_EVIDENCE",
];

pub struct Finding {
    pub bundle_id: Option<String>,
    pub path: Option<String>,
    pub code: String,
    pub detail: String,
}

fn finding(bundle_id: Option<&str>, path: Option<&str>, code: &str, detail: String) -> Finding {
    Finding {
        bundle_id: bundle_id.map(String::from),
        path: path.map(String::from),
        code: code.to_string(),
        detail,
    }
}

fn overlay_prefix_re() -> Regex {
    Regex::new(r"(?i)^(?:<project-overlay>|<workspace>|<studio-workspace-root>|<CURRENT_WORKSPACE>|<package-root>|<audit-skill-dir>|<[a-z][a-z0-9-]*>)").unwrap()
}
fn unresolved_marker_re() -> Regex {
    Regex::new(r"(?i)\b(?:TODO|FIXME|XXX)\b\s*:?\s*(?:no in-package|not available|missing|unresolved)").unwrap()
}
fn script_reference_re() -> Regex {
    Regex::new(r"`(?:scripts/|\.{1,2}/)[A-Za-z0-9._\-/]+\.(?:mjs|js|py|sh|ps1|vbs)`").unwrap()
}
fn placeholder_re() -> Regex {
    Regex::new(r"(?i)(?:^|/)(?:xxx|yyy|foo|bar|example|placeholder)\.[a-z0-9]+$").unwrap()
}
fn document_re() -> Regex {
    Regex::new(r"(?i)\.(?:md|mdx|txt)$").unwrap()
}
fn inline_code_re() -> Regex {
    Regex::new(r"`([^`\r\n]+)`").unwrap()
}
fn fenced_code_re() -> Regex {
    Regex::new(r"(?s)```[^\r\n]*\r?\n(.*?)```").unwrap()
}
fn command_start_re() -> Regex {
    Regex::new(r"^(?:[$>]\s*)?([A-Za-z0-9][A-Za-z0-9._-]*)\b").unwrap()
}
fn host_capability_directive_re() -> Regex {
    Regex::new(r"(?i)\bREQUIRES_HOST_CAPABILITY:\s*([a-z][a-z0-9-]*)").unwrap()
}

pub fn parse_dependency_declaration(text: &str, path: &str) -> Result<Value, String> {
    let document: Value = serde_json::from_str(text)
        .map_err(|_| format!("{path}: dependency declaration is not valid JSON"))?;
    if !document.is_object() {
        return Err(format!("{path}: dependency declaration must be an object"));
    }
    let allowed: HashSet<&str> = ["schemaVersion", "kind", "resources"].into_iter().collect();
    for key in document.as_object().unwrap().keys() {
        if !allowed.contains(key.as_str()) {
            return Err(format!("{path}: unknown dependency declaration field {key}"));
        }
    }
    if document.get("schemaVersion").and_then(|v| v.as_i64()) != Some(1)
        || document.get("kind").and_then(|v| v.as_str()) != Some("legion-skill-dependencies")
    {
        return Err(format!("{path}: dependency declaration has an unsupported schema"));
    }
    if !document.get("resources").map(|v| v.is_array()).unwrap_or(false) {
        return Err(format!("{path}: dependency declaration resources must be an array"));
    }
    Ok(document)
}

struct LoadedDeclaration {
    document: Option<Value>,
    error: Option<String>,
}

fn load_dependency_declaration(skill_root: &Path) -> LoadedDeclaration {
    let path = skill_root.join(DEPENDENCY_DECLARATION);
    if !path.is_file() {
        return LoadedDeclaration {
            document: None,
            error: Some("missing dependency declaration".to_string()),
        };
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            return LoadedDeclaration {
                document: None,
                error: Some(e.to_string()),
            }
        }
    };
    match parse_dependency_declaration(&text, &path.display().to_string()) {
        Ok(doc) => LoadedDeclaration { document: Some(doc), error: None },
        Err(e) => LoadedDeclaration { document: None, error: Some(e) },
    }
}

pub struct ClassifyResult {
    pub ok: bool,
    pub code: String,
    pub detail: String,
}

/// JS truthiness for a JSON value (undefined/null/false/0/""/NaN are falsy).
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn ok() -> ClassifyResult {
    ClassifyResult { ok: true, code: String::new(), detail: String::new() }
}
fn bad(code: &str, detail: String) -> ClassifyResult {
    ClassifyResult { ok: false, code: code.to_string(), detail }
}

pub fn classify_resource(
    entry: &Value,
    package_root: &Path,
    skill_root: &Path,
    capabilities: &Value,
) -> ClassifyResult {
    if entry.is_string() {
        return bad(
            "untyped-resource",
            format!("resource is a bare string, not a typed entry: {}", entry.as_str().unwrap()),
        );
    }
    if !entry.is_object() {
        return bad("invalid-resource", format!("resource is not an object: {entry}"));
    }
    let klass = entry.get("class").and_then(|v| v.as_str()).unwrap_or("");
    if !DEPENDENCY_CLASSES.contains(&klass) {
        return bad("unknown-class", format!("resource declares no known dependency class: {entry}"));
    }
    match klass {
        "PACKAGE_INTERNAL" => {
            let path_str = match entry.get("path").and_then(|v| v.as_str()) {
                Some(p) if !p.is_empty() => p,
                _ => return bad("invalid-resource", "PACKAGE_INTERNAL declares no path".to_string()),
            };
            let target = normalize(&skill_root.join(path_str));
            let package_root_n = normalize(package_root);
            if !target.starts_with(&package_root_n) {
                return bad("escapes-package", format!("PACKAGE_INTERNAL escapes the package: {path_str}"));
            }
            if !target.exists() {
                return bad("missing-internal", format!("PACKAGE_INTERNAL does not exist: {path_str}"));
            }
            ok()
        }
        "HOST_CAPABILITY" => {
            let capability = match entry.get("capability").and_then(|v| v.as_str()) {
                Some(c) if !c.is_empty() => c,
                _ => return bad("invalid-resource", "HOST_CAPABILITY names no capability".to_string()),
            };
            if capabilities.get(capability).is_none() {
                return bad(
                    "undeclared-capability",
                    format!("HOST_CAPABILITY is absent from the registry: {capability}"),
                );
            }
            ok()
        }
        "PROJECT_OVERLAY" => {
            if entry.get("optional").and_then(|v| v.as_bool()) != Some(true) {
                let p = entry.get("path").and_then(|v| v.as_str()).unwrap_or("(no path)");
                return bad("mandatory-overlay", format!("PROJECT_OVERLAY must be optional: {p}"));
            }
            if !truthy(entry.get("absent")) {
                let p = entry.get("path").and_then(|v| v.as_str()).unwrap_or("(no path)");
                return bad("undeclared-degradation", format!("PROJECT_OVERLAY states no behaviour when absent: {p}"));
            }
            if let Some(p) = entry.get("path") {
                if !p.is_null() {
                    let s = p.as_str();
                    if s.is_none() || !overlay_prefix_re().is_match(s.unwrap()) {
                        return bad(
                            "concrete-overlay-path",
                            format!("PROJECT_OVERLAY must use a placeholder root, not a concrete path: {p}"),
                        );
                    }
                }
            }
            ok()
        }
        _ => ok(), // HISTORICAL_EVIDENCE is inert by definition.
    }
}

fn normalize(path: &Path) -> PathBuf {
    // `resolve()`-equivalent lexical normalization (no symlink resolution),
    // matching Node's `path.resolve`/`path.relative` semantics closely
    // enough for the escapes-package containment check.
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn scan_packaged_text(text: &str, path: &str, skill_root: &Path, package_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    if unresolved_marker_re().is_match(text) {
        findings.push(finding(
            None,
            Some(path),
            "unresolved-marker",
            "packaged text ships an unresolved TODO in place of a real reference".to_string(),
        ));
    }
    if document_re().is_match(path) {
        let placeholder = placeholder_re();
        for m in script_reference_re().find_iter(text) {
            let reference = &m.as_str()[1..m.as_str().len() - 1];
            if placeholder.is_match(reference) {
                continue;
            }
            let mut candidates = vec![normalize(&package_root.join(reference))];
            let doc_dir = Path::new(path).parent().unwrap_or(Path::new(""));
            let mut dir = normalize(&skill_root.join(doc_dir));
            loop {
                candidates.push(normalize(&dir.join(reference)));
                if dir == skill_root || !dir.starts_with(skill_root) {
                    break;
                }
                let parent = match dir.parent() {
                    Some(p) => p.to_path_buf(),
                    None => break,
                };
                if parent == dir {
                    break;
                }
                dir = parent;
            }
            if !candidates.iter().any(|c| c.exists()) {
                findings.push(finding(
                    None,
                    Some(path),
                    "dangling-script",
                    format!("document promises a script that does not exist: {reference}"),
                ));
            }
        }
    }
    findings
}

fn code_snippets(text: &str) -> Vec<String> {
    let mut snippets = Vec::new();
    for cap in fenced_code_re().captures_iter(text) {
        snippets.push(cap[1].to_string());
    }
    for cap in inline_code_re().captures_iter(text) {
        snippets.push(cap[1].to_string());
    }
    snippets
}

pub fn scan_host_command_references(
    text: &str,
    path: &str,
    command_capabilities: &HashMap<String, String>,
    host_requirements: &HashSet<String>,
    scoped_capabilities: &HashSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let declared: HashSet<&String> = if !scoped_capabilities.is_empty() {
        host_requirements.iter().chain(scoped_capabilities.iter()).collect()
    } else {
        host_requirements.iter().collect()
    };
    let start_re = command_start_re();
    for snippet in code_snippets(text) {
        for line in snippet.split(['\n']) {
            let line = line.trim_end_matches('\r');
            let trimmed = line.trim();
            let command = start_re
                .captures(trimmed)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_lowercase());
            let Some(command) = command else { continue };
            let Some(capability) = command_capabilities.get(&command) else { continue };
            if declared.contains(capability) {
                continue;
            }
            let key = format!("{command}:{capability}");
            if !seen.insert(key) {
                continue;
            }
            findings.push(finding(
                None,
                Some(path),
                "undeclared-host-command",
                format!("command {command} requires declared host capability {capability}"),
            ));
        }
    }
    for cap in host_capability_directive_re().captures_iter(text) {
        let capability = &cap[1];
        if host_requirements.contains(capability) {
            continue;
        }
        findings.push(finding(
            None,
            Some(path),
            "undeclared-host-capability",
            format!("REQUIRES_HOST_CAPABILITY {capability} is absent from dependencies.json and hostRequirements"),
        ));
    }
    findings
}

struct BundleResult {
    findings: Vec<Finding>,
    declaration_count: usize,
    typed_resource_count: usize,
}

fn verify_bundle_dependencies(
    package_root: &Path,
    manifest_id: &str,
    capabilities: &Value,
    command_capabilities: &HashMap<String, String>,
) -> BundleResult {
    let mut findings = Vec::new();
    let skill_root = package_root.join("skills").join(manifest_id);
    let declaration = load_dependency_declaration(&skill_root);
    let relative_path = format!("skills/{manifest_id}/{DEPENDENCY_DECLARATION}");
    let Some(document) = declaration.document else {
        let code = if declaration.error.as_deref() == Some("missing dependency declaration") {
            "missing-dependency-declaration"
        } else {
            "invalid-dependency-declaration"
        };
        findings.push(finding(
            Some(manifest_id),
            Some(&relative_path),
            code,
            declaration.error.unwrap_or_default(),
        ));
        return BundleResult { findings, declaration_count: 0, typed_resource_count: 0 };
    };

    let mut declared: HashSet<String> = HashSet::new();
    let resources = document.get("resources").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for (index, entry) in resources.iter().enumerate() {
        let result = classify_resource(entry, package_root, &skill_root, capabilities);
        if !result.ok {
            findings.push(finding(
                Some(manifest_id),
                Some(&format!("{DEPENDENCY_DECLARATION}#resources.{index}")),
                &result.code,
                result.detail,
            ));
        }
        if entry.get("class").and_then(|v| v.as_str()) == Some("HOST_CAPABILITY") {
            if let Some(cap) = entry.get("capability").and_then(|v| v.as_str()) {
                if declared.contains(cap) {
                    findings.push(finding(
                        Some(manifest_id),
                        Some(&format!("{DEPENDENCY_DECLARATION}#resources.{index}")),
                        "duplicate-host-capability",
                        format!("HOST_CAPABILITY is declared more than once: {cap}"),
                    ));
                }
                declared.insert(cap.to_string());
            }
        }
    }

    let skill_path = skill_root.join("SKILL.md");
    match read_text(&skill_path) {
        Some(text) => match parse_skill_frontmatter(&text, &format!("skills/{manifest_id}/SKILL.md")) {
            Ok(frontmatter) => {
                let required: HashSet<String> = frontmatter.host_requirements.iter().cloned().collect();
                if declared != required {
                    let mut declared_sorted: Vec<&String> = declared.iter().collect();
                    declared_sorted.sort();
                    let mut required_sorted: Vec<&String> = required.iter().collect();
                    required_sorted.sort();
                    let d = declared_sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                    let r = required_sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                    findings.push(finding(
                        Some(manifest_id),
                        Some("SKILL.md"),
                        "host-requirement-mismatch",
                        format!(
                            "SKILL.md hostRequirements ({}) do not match dependencies.json HOST_CAPABILITY entries ({})",
                            if r.is_empty() { "none" } else { &r },
                            if d.is_empty() { "none" } else { &d }
                        ),
                    ));
                }
                let scoped = scoped_host_capabilities(&skill_root);
                for f in scan_host_command_references(&text, "SKILL.md", command_capabilities, &required, &scoped) {
                    findings.push(Finding { bundle_id: Some(manifest_id.to_string()), ..f });
                }
            }
            Err(e) => findings.push(finding(Some(manifest_id), Some("SKILL.md"), "invalid-skill-frontmatter", e)),
        },
        None => findings.push(finding(
            Some(manifest_id),
            Some("SKILL.md"),
            "invalid-skill-frontmatter",
            format!("{}: missing YAML frontmatter opener", skill_path.display()),
        )),
    }

    BundleResult {
        findings,
        declaration_count: 1,
        typed_resource_count: resources.len(),
    }
}

pub fn verify_capability_aliases(package_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path = package_root.join("src/config/capability-aliases.json");
    if !path.is_file() {
        return findings;
    }
    let Ok(document) = read_json(&path) else { return findings };
    let empty = serde_json::Map::new();
    let aliases = document.get("aliases").and_then(|v| v.as_object()).unwrap_or(&empty);
    for (alias, target) in aliases {
        let Some(target) = target.as_str() else { continue };
        if !target.starts_with('/') {
            continue;
        }
        let skill = target[1..].split_whitespace().next().unwrap_or("");
        if !package_root.join("skills").join(skill).join("SKILL.md").exists() {
            findings.push(finding(
                None,
                Some("src/config/capability-aliases.json"),
                "dangling-alias",
                format!("alias {alias} routes to a skill this package does not ship: {target}"),
            ));
        }
    }
    findings
}

pub fn verify_manifest_consumers(package_root: &Path, manifests: &HashMap<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for manifest in manifests.values() {
        let id = manifest.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let consumers = manifest
            .pointer("/parity/consumers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for consumer in consumers {
            let Some(consumer) = consumer.as_str() else { continue };
            if !package_root.join(consumer).exists() {
                findings.push(finding(
                    Some(id),
                    Some(consumer),
                    "stale-consumer",
                    format!("manifest declares a consumer that no longer exists: {consumer}"),
                ));
            }
        }
    }
    findings
}

fn semantic_bundle_ids(package_root: &Path) -> Vec<String> {
    let skills_root = package_root.join("skills");
    if !skills_root.is_dir() {
        return Vec::new();
    }
    let mut ids: Vec<String> = std::fs::read_dir(&skills_root)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_dir() && entry.path().join("SKILL.md").is_file())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    ids.sort();
    ids
}

pub fn verify_manifest_coverage(package_root: &Path, manifests: &HashMap<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let skills_root = package_root.join("skills");
    let declared: HashSet<&String> = manifests.keys().collect();
    for id in semantic_bundle_ids(package_root) {
        if !declared.contains(&id) {
            findings.push(finding(
                Some(&id),
                Some(&format!("skills/{id}/SKILL.md")),
                "missing-skill-manifest",
                "semantic bundle has no manifest and cannot enter dependency closure".to_string(),
            ));
        }
    }
    for manifest in manifests.values() {
        let id = manifest.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if !skills_root.join(id).join("SKILL.md").is_file() {
            findings.push(finding(
                Some(id),
                Some(&format!("skills/{id}/SKILL.md")),
                "missing-skill-entry",
                "manifest declares a semantic bundle whose SKILL.md is absent".to_string(),
            ));
        }
    }
    findings
}

fn verify_route_resources(
    text: &str,
    package_root: &Path,
    skill_root: &Path,
    capabilities: &Value,
    manifest_id: &str,
) -> Vec<Finding> {
    let document: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            return vec![finding(
                Some(manifest_id),
                Some("references/route-resources.json"),
                "invalid-resource-document",
                "route resource table is not valid JSON".to_string(),
            )]
        }
    };
    let mut findings = Vec::new();
    let Some(sections) = document.as_object() else { return findings };
    for (section, table) in sections {
        let Some(table) = table.as_object() else { continue };
        for (key, entries) in table {
            let Some(entries) = entries.as_array() else { continue };
            for entry in entries {
                let result = classify_resource(entry, package_root, skill_root, capabilities);
                if !result.ok {
                    findings.push(finding(
                        Some(manifest_id),
                        Some(&format!("references/route-resources.json#{section}.{key}")),
                        &result.code,
                        result.detail,
                    ));
                }
            }
        }
    }
    findings
}

fn all_files(directory: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(all_files(&path));
        } else if path.is_file() {
            out.push(path);
        }
    }
    out
}

pub struct ClosureResult {
    pub ok: bool,
    pub findings: Vec<Finding>,
    pub semantic_bundles: usize,
    pub dependency_declarations: usize,
    pub typed_resources: usize,
}

pub fn verify_dependency_closure(
    package_root: &Path,
    manifests: &HashMap<String, Value>,
) -> Result<ClosureResult, String> {
    let registry = load_capability_registry(package_root)?;
    let capabilities = registry.get("capabilities").cloned().unwrap_or_else(|| serde_json::json!({}));
    let command_capabilities = command_capability_map(&registry)?;

    let mut findings = Vec::new();
    findings.extend(verify_manifest_consumers(package_root, manifests));
    findings.extend(verify_manifest_coverage(package_root, manifests));
    findings.extend(verify_capability_aliases(package_root));

    let mut declaration_count = 0usize;
    let mut typed_resource_count = 0usize;

    let file_ext_re = Regex::new(r"(?i)\.(?:md|mdx|txt|json|ya?ml|mjs|js|py|sh|ps1|vbs)$").unwrap();

    for manifest in manifests.values() {
        let id = manifest.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let skill_root = package_root.join("skills").join(&id);
        if !skill_root.is_dir() {
            continue;
        }
        let declaration = verify_bundle_dependencies(package_root, &id, &capabilities, &command_capabilities);
        findings.extend(declaration.findings);
        declaration_count += declaration.declaration_count;
        typed_resource_count += declaration.typed_resource_count;

        for file in all_files(&skill_root) {
            let relative_path = file
                .strip_prefix(&skill_root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            if !file_ext_re.is_match(&relative_path) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&file) else { continue };
            for f in scan_packaged_text(&text, &relative_path, &skill_root, package_root) {
                findings.push(Finding { bundle_id: Some(id.clone()), ..f });
            }
            if relative_path.ends_with("route-resources.json") {
                findings.extend(verify_route_resources(&text, package_root, &skill_root, &capabilities, &id));
            }
        }
    }

    Ok(ClosureResult {
        ok: findings.is_empty(),
        findings,
        semantic_bundles: semantic_bundle_ids(package_root).len(),
        dependency_declarations: declaration_count,
        typed_resources: typed_resource_count,
    })
}

pub fn run(root: &Path) -> bool {
    let manifest_dir = root.join("skills/manifests");
    let mut manifests: HashMap<String, Value> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&manifest_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") || name.ends_with(".import-receipt.json") {
                continue;
            }
            match read_json(&entry.path()) {
                Ok(manifest) => {
                    if let Some(id) = manifest.get("id").and_then(|v| v.as_str()) {
                        manifests.insert(id.to_string(), manifest);
                    }
                }
                Err(e) => {
                    eprintln!("dependency closure failed: {e}");
                    return false;
                }
            }
        }
    }

    let result = match verify_dependency_closure(root, &manifests) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dependency closure failed: {e}");
            return false;
        }
    };

    if result.ok {
        println!(
            "dependency closure ok: {}/{} declarations, {} typed resources",
            result.dependency_declarations, result.semantic_bundles, result.typed_resources
        );
        return true;
    }
    for f in &result.findings {
        eprintln!(
            "{}: {}/{} — {}",
            f.code,
            f.bundle_id.as_deref().unwrap_or("-"),
            f.path.as_deref().unwrap_or("-"),
            f.detail
        );
    }
    eprintln!("\ndependency closure failed: {} finding(s)", result.findings.len());
    // JS exits 6 specifically on findings (vs. 1 for other failures); exit
    // directly here so the caller sees the same code.
    std::process::exit(6);
}
