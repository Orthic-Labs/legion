//! Dependency-closure validation.
//!
//! Ported from `src/lib/skills/dependency-closure.mjs`. Every packaged
//! semantic bundle owns one typed dependency declaration. A declaration
//! classifies package resources, host capabilities, project overlays, and
//! historical evidence before a host projects or invokes that bundle.

use crate::l5_skills::skill_frontmatter::parse_skill_frontmatter;
use crate::p7_host::capabilities::command_capability_map;
use crate::wf_port::w2_056::route_resources::scoped_host_capabilities;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const DEPENDENCY_CLASSES: [&str; 4] =
    ["PACKAGE_INTERNAL", "HOST_CAPABILITY", "PROJECT_OVERLAY", "HISTORICAL_EVIDENCE"];

pub const DEPENDENCY_DECLARATION: &str = "dependencies.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyClass {
    PackageInternal,
    HostCapability,
    ProjectOverlay,
    HistoricalEvidence,
}

impl DependencyClass {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "PACKAGE_INTERNAL" => Some(Self::PackageInternal),
            "HOST_CAPABILITY" => Some(Self::HostCapability),
            "PROJECT_OVERLAY" => Some(Self::ProjectOverlay),
            "HISTORICAL_EVIDENCE" => Some(Self::HistoricalEvidence),
            _ => None,
        }
    }
}

static OVERLAY_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:<project-overlay>|<workspace>|<studio-workspace-root>|<CURRENT_WORKSPACE>|<package-root>|<audit-skill-dir>|<[a-z][a-z0-9-]*>)").unwrap()
});
static UNRESOLVED_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:TODO|FIXME|XXX)\b\s*:?\s*(?:no in-package|not available|missing|unresolved)").unwrap()
});
static SCRIPT_REFERENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"`(?:scripts/|\.{1,2}/)[A-Za-z0-9._\-/]+\.(?:mjs|js|py|sh|ps1|vbs)`").unwrap());
static PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|/)(?:xxx|yyy|foo|bar|example|placeholder)\.[a-z0-9]+$").unwrap());
static DOCUMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.(?:md|mdx|txt)$").unwrap());
static INLINE_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`([^`\r\n]+)`").unwrap());
static FENCED_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)```[^\r\n]*\r?\n(.*?)```").unwrap());
static COMMAND_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[$>]\s*)?([A-Za-z0-9][A-Za-z0-9._-]*)\b").unwrap());
static HOST_CAPABILITY_DIRECTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bREQUIRES_HOST_CAPABILITY:\s*([a-z][a-z0-9-]*)").unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureFinding {
    pub bundle_id: Option<String>,
    pub path: String,
    pub code: &'static str,
    pub detail: String,
}

fn f(bundle_id: Option<&str>, path: impl Into<String>, code: &'static str, detail: impl Into<String>) -> ClosureFinding {
    ClosureFinding { bundle_id: bundle_id.map(String::from), path: path.into(), code, detail: detail.into() }
}

/// Port of `parseDependencyDeclaration`.
pub fn parse_dependency_declaration(text: &str, path: &str) -> Result<Value, String> {
    let document: Value = serde_json::from_str(text)
        .map_err(|_| format!("{path}: dependency declaration is not valid JSON"))?;
    let Some(object) = document.as_object() else {
        return Err(format!("{path}: dependency declaration must be an object"));
    };
    let allowed = ["schemaVersion", "kind", "resources"];
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{path}: unknown dependency declaration field {key}"));
        }
    }
    if object.get("schemaVersion") != Some(&Value::from(1))
        || object.get("kind").and_then(Value::as_str) != Some("legion-skill-dependencies")
    {
        return Err(format!("{path}: dependency declaration has an unsupported schema"));
    }
    if !object.get("resources").map(Value::is_array).unwrap_or(false) {
        return Err(format!("{path}: dependency declaration resources must be an array"));
    }
    Ok(document)
}

struct LoadedDeclaration {
    path: String,
    document: Option<Value>,
    error: Option<String>,
}

fn load_dependency_declaration(skill_root: &Path) -> LoadedDeclaration {
    let path = skill_root.join(DEPENDENCY_DECLARATION);
    let path_display = path.to_string_lossy().into_owned();
    if !path.exists() {
        return LoadedDeclaration { path: path_display, document: None, error: Some("missing dependency declaration".to_string()) };
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => match parse_dependency_declaration(&text, &path_display) {
            Ok(document) => LoadedDeclaration { path: path_display, document: Some(document), error: None },
            Err(error) => LoadedDeclaration { path: path_display, document: None, error: Some(error) },
        },
        Err(error) => LoadedDeclaration { path: path_display, document: None, error: Some(error.to_string()) },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceClassification {
    pub ok: bool,
    pub code: &'static str,
    pub detail: String,
}

fn ok() -> ResourceClassification {
    ResourceClassification { ok: true, code: "", detail: String::new() }
}
fn bad(code: &'static str, detail: impl Into<String>) -> ResourceClassification {
    ResourceClassification { ok: false, code, detail: detail.into() }
}

/// Classify one typed resource entry from a canonical dependency
/// declaration or route table. Port of `classifyResource`.
pub fn classify_resource(
    entry: &Value,
    package_root: &Path,
    skill_root: &Path,
    capabilities: &Value,
) -> ResourceClassification {
    if entry.is_string() {
        return bad("untyped-resource", format!("resource is a bare string, not a typed entry: {}", entry.as_str().unwrap()));
    }
    let Some(object) = entry.as_object() else {
        return bad("invalid-resource", format!("resource is not an object: {entry}"));
    };
    let klass_str = object.get("class").and_then(Value::as_str).unwrap_or("");
    let Some(klass) = DependencyClass::parse(klass_str) else {
        return bad("unknown-class", format!("resource declares no known dependency class: {entry}"));
    };
    match klass {
        DependencyClass::PackageInternal => {
            let Some(path) = object.get("path").and_then(Value::as_str) else {
                return bad("invalid-resource", "PACKAGE_INTERNAL declares no path");
            };
            let target = normalize(&skill_root.join(path));
            let root = normalize(package_root);
            let contained = target.strip_prefix(&root);
            let escapes = match contained {
                Ok(rel) => rel == Path::new("..") || rel.starts_with(".."),
                Err(_) => true,
            };
            if escapes {
                return bad("escapes-package", format!("PACKAGE_INTERNAL escapes the package: {path}"));
            }
            if !target.exists() {
                return bad("missing-internal", format!("PACKAGE_INTERNAL does not exist: {path}"));
            }
            ok()
        }
        DependencyClass::HostCapability => {
            let Some(capability) = object.get("capability").and_then(Value::as_str) else {
                return bad("invalid-resource", "HOST_CAPABILITY names no capability");
            };
            let declared = capabilities.get("capabilities").and_then(|c| c.get(capability)).is_some();
            if !declared {
                return bad("undeclared-capability", format!("HOST_CAPABILITY is absent from the registry: {capability}"));
            }
            ok()
        }
        DependencyClass::ProjectOverlay => {
            if object.get("optional").and_then(Value::as_bool) != Some(true) {
                let path = object.get("path").and_then(Value::as_str).unwrap_or("(no path)");
                return bad("mandatory-overlay", format!("PROJECT_OVERLAY must be optional: {path}"));
            }
            if object.get("absent").is_none() || object.get("absent") == Some(&Value::Null) {
                let path = object.get("path").and_then(Value::as_str).unwrap_or("(no path)");
                return bad("undeclared-degradation", format!("PROJECT_OVERLAY states no behaviour when absent: {path}"));
            }
            if let Some(path_value) = object.get("path") {
                if !path_value.is_null() {
                    let is_valid_string_prefix = path_value.as_str().map(|p| OVERLAY_PREFIX.is_match(p)).unwrap_or(false);
                    if !is_valid_string_prefix {
                        return bad("concrete-overlay-path", format!("PROJECT_OVERLAY must use a placeholder root, not a concrete path: {path_value}"));
                    }
                }
            }
            ok()
        }
        DependencyClass::HistoricalEvidence => ok(), // inert by definition.
    }
}

fn normalize(path: &Path) -> PathBuf {
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

/// Scan a packaged text file for references that resolve into no class at
/// all. Port of `scanPackagedText`.
pub fn scan_packaged_text(text: &str, path: &str, skill_root: &Path, package_root: &Path) -> Vec<ClosureFinding> {
    let mut findings = Vec::new();
    if UNRESOLVED_MARKER.is_match(text) {
        findings.push(f(None, path, "unresolved-marker", "packaged text ships an unresolved TODO in place of a real reference"));
    }
    if DOCUMENT.is_match(path) {
        let skill_root = normalize(skill_root);
        for m in SCRIPT_REFERENCE.find_iter(text) {
            let matched = m.as_str();
            let reference = &matched[1..matched.len() - 1];
            if PLACEHOLDER.is_match(reference) {
                continue;
            }
            let mut candidates = vec![normalize(&package_root.join(reference))];
            let doc_dir = Path::new(path).parent().unwrap_or(Path::new(""));
            let mut dir = normalize(&skill_root.join(doc_dir));
            loop {
                candidates.push(normalize(&dir.join(reference)));
                if dir == skill_root || !dir.starts_with(&skill_root) {
                    break;
                }
                let Some(parent) = dir.parent() else { break };
                dir = parent.to_path_buf();
            }
            if !candidates.iter().any(|candidate| candidate.exists()) {
                findings.push(f(None, path, "dangling-script", format!("document promises a script that does not exist: {reference}")));
            }
        }
    }
    findings
}

fn code_snippets(text: &str) -> Vec<String> {
    let mut snippets = Vec::new();
    for m in FENCED_CODE.captures_iter(text) {
        snippets.push(m[1].to_string());
    }
    for m in INLINE_CODE.captures_iter(text) {
        snippets.push(m[1].to_string());
    }
    snippets
}

/// Reject use of a registry-owned executable command without its host
/// requirement. Port of `scanHostCommandReferences`.
pub fn scan_host_command_references(
    text: &str,
    path: &str,
    command_capabilities: &BTreeMap<String, String>,
    host_requirements: &BTreeSet<String>,
    scoped_capabilities: &BTreeSet<String>,
) -> Vec<ClosureFinding> {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    let declared: BTreeSet<&String> = if scoped_capabilities.is_empty() {
        host_requirements.iter().collect()
    } else {
        host_requirements.iter().chain(scoped_capabilities.iter()).collect()
    };
    for snippet in code_snippets(text) {
        for line in snippet.split(['\n', '\r']) {
            let Some(captures) = COMMAND_START.captures(line.trim()) else { continue };
            let command = captures[1].to_ascii_lowercase();
            let Some(capability) = command_capabilities.get(&command) else { continue };
            if declared.contains(capability) {
                continue;
            }
            let key = format!("{command}:{capability}");
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            findings.push(f(None, path, "undeclared-host-command", format!("command {command} requires declared host capability {capability}")));
        }
    }
    for captures in HOST_CAPABILITY_DIRECTIVE.captures_iter(text) {
        let capability = &captures[1];
        if host_requirements.contains(capability) {
            continue;
        }
        findings.push(f(None, path, "undeclared-host-capability", format!("REQUIRES_HOST_CAPABILITY {capability} is absent from dependencies.json and hostRequirements")));
    }
    findings
}

fn same_members(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left == right
}

struct BundleDependencyResult {
    findings: Vec<ClosureFinding>,
    declaration_count: usize,
    typed_resource_count: usize,
}

fn verify_bundle_dependencies(
    package_root: &Path,
    manifest_id: &str,
    capabilities: &Value,
    command_capabilities: &BTreeMap<String, String>,
) -> BundleDependencyResult {
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
        findings.push(f(Some(manifest_id), relative_path, code, declaration.error.unwrap_or_default()));
        return BundleDependencyResult { findings, declaration_count: 0, typed_resource_count: 0 };
    };

    let resources = document.get("resources").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for (index, entry) in resources.iter().enumerate() {
        let result = classify_resource(entry, package_root, &skill_root, capabilities);
        if !result.ok {
            findings.push(f(Some(manifest_id), format!("{DEPENDENCY_DECLARATION}#resources.{index}"), result.code, result.detail));
        }
        if entry.get("class").and_then(Value::as_str) == Some("HOST_CAPABILITY") {
            if let Some(capability) = entry.get("capability").and_then(Value::as_str) {
                if declared.contains(capability) {
                    findings.push(f(
                        Some(manifest_id),
                        format!("{DEPENDENCY_DECLARATION}#resources.{index}"),
                        "duplicate-host-capability",
                        format!("HOST_CAPABILITY is declared more than once: {capability}"),
                    ));
                }
                declared.insert(capability.to_string());
            }
        }
    }

    let skill_path = skill_root.join("SKILL.md");
    match std::fs::read_to_string(&skill_path) {
        Ok(text) => match parse_skill_frontmatter(&text, &format!("skills/{manifest_id}/SKILL.md")) {
            Ok(frontmatter) => {
                let required: BTreeSet<String> = frontmatter.list("hostRequirements").into_iter().map(String::from).collect();
                if !same_members(&declared, &required) {
                    let declared_sorted: Vec<&String> = declared.iter().collect();
                    let required_sorted: Vec<&String> = required.iter().collect();
                    findings.push(f(
                        Some(manifest_id),
                        "SKILL.md",
                        "host-requirement-mismatch",
                        format!(
                            "SKILL.md hostRequirements ({}) do not match dependencies.json HOST_CAPABILITY entries ({})",
                            if required_sorted.is_empty() { "none".to_string() } else { required_sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") },
                            if declared_sorted.is_empty() { "none".to_string() } else { declared_sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") },
                        ),
                    ));
                }
                let scoped = scoped_host_capabilities(&skill_root);
                for finding in scan_host_command_references(&text, "SKILL.md", command_capabilities, &required, &scoped) {
                    findings.push(ClosureFinding { bundle_id: Some(manifest_id.to_string()), ..finding });
                }
            }
            Err(error) => findings.push(f(Some(manifest_id), "SKILL.md", "invalid-skill-frontmatter", error)),
        },
        Err(error) => findings.push(f(Some(manifest_id), "SKILL.md", "invalid-skill-frontmatter", error.to_string())),
    }

    let typed_resource_count = resources.len();
    BundleDependencyResult { findings, declaration_count: 1, typed_resource_count }
}

/// Validate that every capability alias points at a skill this package
/// actually ships. Port of `verifyCapabilityAliases`.
pub fn verify_capability_aliases(package_root: &Path) -> Vec<ClosureFinding> {
    let mut findings = Vec::new();
    let path = package_root.join("src/config/capability-aliases.json");
    let Ok(text) = std::fs::read_to_string(&path) else { return findings };
    let Ok(document) = serde_json::from_str::<Value>(&text) else { return findings };
    let Some(aliases) = document.get("aliases").and_then(Value::as_object) else { return findings };
    for (alias, target) in aliases {
        let Some(target_str) = target.as_str() else { continue };
        if !target_str.starts_with('/') {
            continue;
        }
        let skill = target_str[1..].split_whitespace().next().unwrap_or("");
        if !package_root.join("skills").join(skill).join("SKILL.md").exists() {
            findings.push(f(
                None,
                "src/config/capability-aliases.json",
                "dangling-alias",
                format!("alias {alias} routes to a skill this package does not ship: {target_str}"),
            ));
        }
    }
    findings
}

/// Validate that every manifest's declared consumers actually exist. Port
/// of `verifyManifestConsumers`.
pub fn verify_manifest_consumers(package_root: &Path, manifests: &BTreeMap<String, Value>) -> Vec<ClosureFinding> {
    let mut findings = Vec::new();
    for (id, manifest) in manifests {
        let consumers = manifest
            .get("parity")
            .and_then(|p| p.get("consumers"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for consumer in consumers {
            let Some(consumer) = consumer.as_str() else { continue };
            if !package_root.join(consumer).exists() {
                findings.push(f(Some(id.as_str()), consumer, "stale-consumer", format!("manifest declares a consumer that no longer exists: {consumer}")));
            }
        }
    }
    findings
}

/// Every semantic `SKILL.md` participates in closure; no unmanifested
/// bundle may bypass it.
fn semantic_bundle_ids(package_root: &Path) -> Vec<String> {
    let skills_root = package_root.join("skills");
    let Ok(entries) = std::fs::read_dir(&skills_root) else { return Vec::new() };
    let mut ids: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir() && entry.path().join("SKILL.md").exists())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    ids.sort();
    ids
}

/// Port of `verifyManifestCoverage`.
pub fn verify_manifest_coverage(package_root: &Path, manifests: &BTreeMap<String, Value>) -> Vec<ClosureFinding> {
    let mut findings = Vec::new();
    let skills_root = package_root.join("skills");
    let declared: BTreeSet<&String> = manifests.keys().collect();
    for id in semantic_bundle_ids(package_root) {
        if !declared.contains(&id) {
            findings.push(f(Some(id.as_str()), format!("skills/{id}/SKILL.md"), "missing-skill-manifest", "semantic bundle has no manifest and cannot enter dependency closure"));
        }
    }
    for id in manifests.keys() {
        if !skills_root.join(id).join("SKILL.md").exists() {
            findings.push(f(Some(id.as_str()), format!("skills/{id}/SKILL.md"), "missing-skill-entry", "manifest declares a semantic bundle whose SKILL.md is absent"));
        }
    }
    findings
}

fn verify_route_resources(text: &str, package_root: &Path, skill_root: &Path, capabilities: &Value, manifest_id: &str) -> Vec<ClosureFinding> {
    let Ok(document) = serde_json::from_str::<Value>(text) else {
        return vec![f(Some(manifest_id), "references/route-resources.json", "invalid-resource-document", "route resource table is not valid JSON")];
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
                    findings.push(f(
                        Some(manifest_id),
                        format!("references/route-resources.json#{section}.{key}"),
                        result.code,
                        result.detail,
                    ));
                }
            }
        }
    }
    findings
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClosureSummary {
    pub semantic_bundles: usize,
    pub dependency_declarations: usize,
    pub typed_resources: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureResult {
    pub ok: bool,
    pub findings: Vec<ClosureFinding>,
    pub summary: ClosureSummary,
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

/// Port of `verifyDependencyClosure`. `registry` is the already-loaded and
/// validated capability registry document (the JS `loadCapabilityRegistry`
/// I/O is left to the caller, mirroring how this crate already splits
/// registry loading from validation in `p7_host::capabilities`).
pub fn verify_dependency_closure(
    package_root: &Path,
    manifests: &BTreeMap<String, Value>,
    registry: &Value,
) -> Result<ClosureResult, String> {
    let command_capabilities = command_capability_map(registry).map_err(|error| error.to_string())?;
    let mut findings = Vec::new();
    findings.extend(verify_manifest_consumers(package_root, manifests));
    findings.extend(verify_manifest_coverage(package_root, manifests));
    findings.extend(verify_capability_aliases(package_root));

    let mut declaration_count = 0;
    let mut typed_resource_count = 0;

    for (id, _manifest) in manifests {
        let skill_root = package_root.join("skills").join(id);
        if !skill_root.exists() {
            continue;
        }
        let declaration = verify_bundle_dependencies(package_root, id, registry, &command_capabilities);
        findings.extend(declaration.findings);
        declaration_count += declaration.declaration_count;
        typed_resource_count += declaration.typed_resource_count;

        for file in all_files(&skill_root) {
            let relative_path = file.strip_prefix(&skill_root).unwrap_or(&file).to_string_lossy().replace('\\', "/");
            let lower = relative_path.to_ascii_lowercase();
            let matches_ext = ["md", "mdx", "txt", "json", "yml", "yaml", "mjs", "js", "py", "sh", "ps1", "vbs"]
                .iter()
                .any(|ext| lower.ends_with(&format!(".{ext}")));
            if !matches_ext {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&file) else { continue };
            for finding in scan_packaged_text(&text, &relative_path, &skill_root, package_root) {
                findings.push(ClosureFinding { bundle_id: Some(id.clone()), ..finding });
            }
            if relative_path.ends_with("route-resources.json") {
                findings.extend(verify_route_resources(&text, package_root, &skill_root, registry, id));
            }
        }
    }

    let ok = findings.is_empty();
    Ok(ClosureResult {
        ok,
        findings,
        summary: ClosureSummary {
            semantic_bundles: semantic_bundle_ids(package_root).len(),
            dependency_declarations: declaration_count,
            typed_resources: typed_resource_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::w2_056::test_support::TempDir;
    use serde_json::json;

    fn registry() -> Value {
        json!({
            "capabilities": {
                "browser-automation": {"kind": "tool", "summary": "s", "degradation": "d", "remedy": "r", "commands": ["chrome"]}
            }
        })
    }

    #[test]
    fn parse_declaration_rejects_bad_schema() {
        assert!(parse_dependency_declaration("not json", "d.json").is_err());
        assert!(parse_dependency_declaration("[]", "d.json").is_err());
        assert!(parse_dependency_declaration(r#"{"schemaVersion":1,"kind":"x","resources":[]}"#, "d.json").is_err());
        assert!(parse_dependency_declaration(r#"{"schemaVersion":1,"kind":"legion-skill-dependencies","resources":{}}"#, "d.json").is_err());
        assert!(parse_dependency_declaration(r#"{"schemaVersion":1,"kind":"legion-skill-dependencies","unknown":true,"resources":[]}"#, "d.json").is_err());
        assert!(parse_dependency_declaration(r#"{"schemaVersion":1,"kind":"legion-skill-dependencies","resources":[]}"#, "d.json").is_ok());
    }

    #[test]
    fn classify_resource_package_internal() {
        let dir = TempDir::new();
        std::fs::create_dir_all(dir.path().join("skills/demo")).unwrap();
        std::fs::write(dir.path().join("skills/demo/scripts.txt"), "x").unwrap();
        let skill_root = dir.path().join("skills/demo");

        let ok_entry = json!({"class": "PACKAGE_INTERNAL", "path": "scripts.txt"});
        assert!(classify_resource(&ok_entry, dir.path(), &skill_root, &registry()).ok);

        let missing_entry = json!({"class": "PACKAGE_INTERNAL", "path": "nope.txt"});
        let result = classify_resource(&missing_entry, dir.path(), &skill_root, &registry());
        assert!(!result.ok);
        assert_eq!(result.code, "missing-internal");

        // `skill_root` is `packageRoot/skills/demo`: two `..` only walks back
        // up to `packageRoot` itself (landing on `packageRoot/outside.txt`,
        // still contained); a third `..` is required to actually escape, per
        // `resolve(skillRoot, entry.path)` / `relative(packageRoot, target)`
        // in dependency-closure.mjs (verified against Node's `path` module).
        let escape_entry = json!({"class": "PACKAGE_INTERNAL", "path": "../../../outside.txt"});
        let result = classify_resource(&escape_entry, dir.path(), &skill_root, &registry());
        assert!(!result.ok);
        assert_eq!(result.code, "escapes-package");
    }

    #[test]
    fn classify_resource_host_capability() {
        let dir = TempDir::new();
        let skill_root = dir.path().join("skills/demo");
        let ok_entry = json!({"class": "HOST_CAPABILITY", "capability": "browser-automation"});
        assert!(classify_resource(&ok_entry, dir.path(), &skill_root, &registry()).ok);

        let bad_entry = json!({"class": "HOST_CAPABILITY", "capability": "nope"});
        let result = classify_resource(&bad_entry, dir.path(), &skill_root, &registry());
        assert_eq!(result.code, "undeclared-capability");
    }

    #[test]
    fn classify_resource_project_overlay() {
        let dir = TempDir::new();
        let skill_root = dir.path().join("skills/demo");

        let mandatory = json!({"class": "PROJECT_OVERLAY", "path": "<workspace>/x"});
        assert_eq!(classify_resource(&mandatory, dir.path(), &skill_root, &registry()).code, "mandatory-overlay");

        let no_absent = json!({"class": "PROJECT_OVERLAY", "optional": true, "path": "<workspace>/x"});
        assert_eq!(classify_resource(&no_absent, dir.path(), &skill_root, &registry()).code, "undeclared-degradation");

        let concrete_path = json!({"class": "PROJECT_OVERLAY", "optional": true, "absent": "skip", "path": "/etc/passwd"});
        assert_eq!(classify_resource(&concrete_path, dir.path(), &skill_root, &registry()).code, "concrete-overlay-path");

        let good = json!({"class": "PROJECT_OVERLAY", "optional": true, "absent": "skip", "path": "<workspace>/x"});
        assert!(classify_resource(&good, dir.path(), &skill_root, &registry()).ok);
    }

    #[test]
    fn classify_resource_historical_evidence_is_inert() {
        let dir = TempDir::new();
        let skill_root = dir.path().join("skills/demo");
        let entry = json!({"class": "HISTORICAL_EVIDENCE"});
        assert!(classify_resource(&entry, dir.path(), &skill_root, &registry()).ok);
    }

    #[test]
    fn classify_resource_untyped_and_invalid() {
        let dir = TempDir::new();
        let skill_root = dir.path().join("skills/demo");
        assert_eq!(classify_resource(&json!("bare"), dir.path(), &skill_root, &registry()).code, "untyped-resource");
        assert_eq!(classify_resource(&json!([1, 2]), dir.path(), &skill_root, &registry()).code, "invalid-resource");
        assert_eq!(classify_resource(&json!({"class": "NOPE"}), dir.path(), &skill_root, &registry()).code, "unknown-class");
    }

    #[test]
    fn scan_packaged_text_flags_unresolved_marker_and_dangling_script() {
        let dir = TempDir::new();
        std::fs::create_dir_all(dir.path().join("skills/demo")).unwrap();
        let skill_root = dir.path().join("skills/demo");

        let text = "TODO: no in-package alternative yet\nsee `scripts/build.mjs` for detail";
        let findings = scan_packaged_text(text, "SKILL.md", &skill_root, dir.path());
        assert!(findings.iter().any(|x| x.code == "unresolved-marker"));
        assert!(findings.iter().any(|x| x.code == "dangling-script"));
    }

    #[test]
    fn scan_packaged_text_resolves_existing_script() {
        let dir = TempDir::new();
        std::fs::create_dir_all(dir.path().join("skills/demo/scripts")).unwrap();
        std::fs::write(dir.path().join("skills/demo/scripts/build.mjs"), "x").unwrap();
        let skill_root = dir.path().join("skills/demo");

        let text = "see `scripts/build.mjs` for detail";
        let findings = scan_packaged_text(text, "SKILL.md", &skill_root, dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_packaged_text_ignores_placeholder_reference() {
        let dir = TempDir::new();
        std::fs::create_dir_all(dir.path().join("skills/demo")).unwrap();
        let skill_root = dir.path().join("skills/demo");
        let text = "see `scripts/example.mjs` for detail";
        let findings = scan_packaged_text(text, "SKILL.md", &skill_root, dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_host_command_references_flags_undeclared_command_and_directive() {
        let mut commands = BTreeMap::new();
        commands.insert("chrome".to_string(), "browser-automation".to_string());
        let host_requirements: BTreeSet<String> = BTreeSet::new();
        let scoped: BTreeSet<String> = BTreeSet::new();

        let text = "```bash\nchrome --headless\n```\nREQUIRES_HOST_CAPABILITY: browser-automation";
        let findings = scan_host_command_references(text, "SKILL.md", &commands, &host_requirements, &scoped);
        assert!(findings.iter().any(|x| x.code == "undeclared-host-command"));
        assert!(findings.iter().any(|x| x.code == "undeclared-host-capability"));
    }

    #[test]
    fn scan_host_command_references_respects_scoped_declaration() {
        let mut commands = BTreeMap::new();
        commands.insert("chrome".to_string(), "browser-automation".to_string());
        let host_requirements: BTreeSet<String> = BTreeSet::new();
        let mut scoped: BTreeSet<String> = BTreeSet::new();
        scoped.insert("browser-automation".to_string());

        let text = "`chrome --headless`";
        let findings = scan_host_command_references(text, "SKILL.md", &commands, &host_requirements, &scoped);
        assert!(findings.is_empty());
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn skill_md(host_requirements: &str) -> String {
        format!(
            "---\nname: demo\ndescription: A demo skill\nkind: capability\ncapabilityClass: workflow\ndiscoverability: public\noperations:\n  - execute\neffects:\n  - process-exec\nhostRequirements:\n{host_requirements}---\nbody\n"
        )
    }

    fn manifest(id: &str) -> Value {
        json!({"id": id})
    }

    #[test]
    fn verify_dependency_closure_clean_bundle_is_ok() {
        let dir = TempDir::new();
        write(dir.path(), "skills/demo/SKILL.md", &skill_md("  - browser-automation\n"));
        write(
            dir.path(),
            "skills/demo/dependencies.json",
            &json!({
                "schemaVersion": 1, "kind": "legion-skill-dependencies",
                "resources": [{"class": "HOST_CAPABILITY", "capability": "browser-automation"}]
            })
            .to_string(),
        );
        let mut manifests = BTreeMap::new();
        manifests.insert("demo".to_string(), manifest("demo"));

        let result = verify_dependency_closure(dir.path(), &manifests, &registry()).unwrap();
        assert!(result.ok, "unexpected findings: {:?}", result.findings);
        assert_eq!(result.summary.semantic_bundles, 1);
        assert_eq!(result.summary.dependency_declarations, 1);
        assert_eq!(result.summary.typed_resources, 1);
    }

    #[test]
    fn verify_dependency_closure_flags_missing_declaration_and_coverage() {
        let dir = TempDir::new();
        write(dir.path(), "skills/undeclared/SKILL.md", &skill_md(""));
        let manifests: BTreeMap<String, Value> = BTreeMap::new();

        let result = verify_dependency_closure(dir.path(), &manifests, &registry()).unwrap();
        assert!(!result.ok);
        assert!(result.findings.iter().any(|x| x.code == "missing-skill-manifest"));
    }

    #[test]
    fn verify_dependency_closure_flags_host_requirement_mismatch() {
        let dir = TempDir::new();
        write(dir.path(), "skills/demo/SKILL.md", &skill_md(""));
        write(
            dir.path(),
            "skills/demo/dependencies.json",
            &json!({
                "schemaVersion": 1, "kind": "legion-skill-dependencies",
                "resources": [{"class": "HOST_CAPABILITY", "capability": "browser-automation"}]
            })
            .to_string(),
        );
        let mut manifests = BTreeMap::new();
        manifests.insert("demo".to_string(), manifest("demo"));

        let result = verify_dependency_closure(dir.path(), &manifests, &registry()).unwrap();
        assert!(result.findings.iter().any(|x| x.code == "host-requirement-mismatch"));
    }

    #[test]
    fn verify_capability_aliases_flags_dangling_alias() {
        let dir = TempDir::new();
        write(
            dir.path(),
            "src/config/capability-aliases.json",
            &json!({"aliases": {"/x": "/missing-skill arg"}}).to_string(),
        );
        let findings = verify_capability_aliases(dir.path());
        assert!(findings.iter().any(|x| x.code == "dangling-alias"));
    }

    #[test]
    fn verify_manifest_consumers_flags_stale_consumer() {
        let dir = TempDir::new();
        let mut manifests = BTreeMap::new();
        manifests.insert(
            "demo".to_string(),
            json!({"id": "demo", "parity": {"consumers": ["src/missing.mjs"]}}),
        );
        let findings = verify_manifest_consumers(dir.path(), &manifests);
        assert!(findings.iter().any(|x| x.code == "stale-consumer"));
    }
}
