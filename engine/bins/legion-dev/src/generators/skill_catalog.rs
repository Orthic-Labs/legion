//! Port of `scripts/generate-skill-catalog.mjs`.

use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

use crate::shared::route_resources::scoped_requirement_details;
use crate::shared::skill_frontmatter::parse_skill_frontmatter_map as parse_skill_frontmatter;

const OUT_INDEX: &str = "src/registry/skills/index.json";
const OUT_DOMAINS: &str = "src/registry/routing/domains.json";

fn list_field(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(String::from)).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) if !s.is_empty() => s.split_whitespace().map(String::from).collect(),
        _ => vec![],
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn canonical_record(id: &str, fm: &Map<String, Value>, registry: &Value, skills_dir: &Path) -> Result<Value, String> {
    let kind = fm.get("kind").and_then(Value::as_str).unwrap_or_default().to_string();
    let capability_class = if kind == "capability" { fm.get("capabilityClass").cloned().unwrap_or(Value::Null) } else { Value::Null };
    let discoverability = fm.get("discoverability").cloned().unwrap_or(Value::Null);
    let domain = fm.get("domain").and_then(Value::as_str).filter(|s| *s != "null" && !s.is_empty()).map(Value::from).unwrap_or(Value::Null);
    let host_requirements = list_field(fm.get("hostRequirements"));
    let mut host_requirement_details = Vec::new();
    for rid in &host_requirements {
        let requirement = registry.get("capabilities").and_then(|c| c.get(rid));
        let requirement = match requirement {
            Some(r) if !r.is_null() => r,
            _ => return Err(format!("skills/{id}/SKILL.md declares host requirement absent from registry: {rid}")),
        };
        let mut o = Map::new();
        o.insert("id".into(), Value::from(rid.clone()));
        o.insert("degradation".into(), requirement.get("degradation").cloned().unwrap_or(Value::Null));
        o.insert("remedy".into(), requirement.get("remedy").cloned().unwrap_or(Value::Null));
        o.insert("probe".into(), requirement.get("probe").cloned().unwrap_or(Value::Null));
        host_requirement_details.push(Value::Object(o));
    }

    let mut out = Map::new();
    out.insert("id".into(), Value::from(id));
    out.insert("name".into(), fm.get("name").cloned().unwrap_or_else(|| Value::from(id)));
    out.insert("description".into(), fm.get("description").cloned().unwrap_or_else(|| Value::from("")));
    out.insert("kind".into(), Value::from(kind));
    out.insert("capabilityClass".into(), capability_class);
    out.insert("discoverability".into(), discoverability);
    // JS left `domain` undefined when the frontmatter omits it, and
    // JSON.stringify drops undefined keys.
    if fm.contains_key("domain") {
        out.insert("domain".into(), domain);
    }
    out.insert("operations".into(), Value::Array(list_field(fm.get("operations")).into_iter().map(Value::from).collect()));
    out.insert("effects".into(), Value::Array(list_field(fm.get("effects")).into_iter().map(Value::from).collect()));
    out.insert("hostRequirements".into(), Value::Array(host_requirements.iter().cloned().map(Value::from).collect()));
    out.insert("hostRequirementDetails".into(), Value::Array(host_requirement_details));
    out.insert(
        "scopedRequirementDetails".into(),
        Value::Array(scoped_requirement_details(&skills_dir.join(id), registry, id)?),
    );
    out.insert("source".into(), Value::from(format!("skills/{id}/SKILL.md")));
    Ok(Value::Object(out))
}

fn validate_aliases(document: &Value, packaged_ids: &std::collections::HashSet<String>) -> Result<(), String> {
    let aliases = document.get("aliases").and_then(Value::as_object).ok_or("capability aliases must be an object")?;
    for (alias, declared) in aliases {
        let declared_str = declared.as_str().ok_or_else(|| format!("invalid capability alias {alias}"))?;
        let valid_alias = alias.starts_with('/')
            && alias.len() > 1
            && alias.as_bytes()[1].is_ascii_lowercase()
            && alias[1..].bytes().all(|b| (b as char).is_ascii_lowercase() || (b as char).is_ascii_digit() || b == b'-');
        if !valid_alias {
            return Err(format!("invalid capability alias {alias}"));
        }
        let mut target = declared_str.split_whitespace().next().unwrap_or("").to_string();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        seen.insert(alias.clone());
        while target.starts_with('/') && aliases.get(&target).and_then(Value::as_str).is_some() {
            if seen.contains(&target) {
                return Err(format!("capability alias cycle at {target}"));
            }
            seen.insert(target.clone());
            let next = aliases.get(&target).and_then(Value::as_str).unwrap_or("");
            target = next.split_whitespace().next().unwrap_or("").to_string();
        }
        if target.starts_with('/') && !packaged_ids.contains(&target[1..]) {
            return Err(format!("alias {alias} targets missing package {target}"));
        }
        if !target.starts_with('/') {
            let valid_hook_tool = {
                let parts: Vec<&str> = target.splitn(2, ':').collect();
                parts.len() == 2
                    && (parts[0] == "hook" || parts[0] == "tool")
                    && !parts[1].is_empty()
                    && parts[1].as_bytes()[0].is_ascii_lowercase()
                    && parts[1].bytes().all(|b| (b as char).is_ascii_lowercase() || (b as char).is_ascii_digit() || b == b'-')
            };
            if !valid_hook_tool {
                return Err(format!("alias {alias} has unsupported target {target}"));
            }
        }
    }
    Ok(())
}

pub fn build_skill_catalog(root: &Path) -> Result<(Value, Value), String> {
    let skills_dir = root.join("skills");
    let registry = read_json(&root.join("src/registry/capabilities.json"))?;
    let mut ids: Vec<String> = fs::read_dir(&skills_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|id| skills_dir.join(id).join("SKILL.md").is_file())
        .collect();
    ids.sort();

    let mut bundles = Vec::new();
    for id in &ids {
        let source = skills_dir.join(id).join("SKILL.md");
        let text = fs::read_to_string(&source).map_err(|e| e.to_string())?;
        let fm = parse_skill_frontmatter(&text, &format!("skills/{id}/SKILL.md"))?;
        let mut record = canonical_record(id, &fm, &registry, &skills_dir)?;
        record.as_object_mut().unwrap().insert("manifest".into(), Value::from(format!("skills/manifests/{id}.json")));
        bundles.push(record);
    }

    let id_set: std::collections::HashSet<String> = ids.iter().cloned().collect();
    validate_aliases(&read_json(&root.join("src/config/capability-aliases.json"))?, &id_set)?;

    let mut index = Map::new();
    index.insert("schemaVersion".into(), Value::from(2));
    index.insert(
        "generatedFrom".into(),
        Value::Array(
            [
                "skills/*/SKILL.md",
                "skills/*/references/route-resources.json",
                "src/config/capability-aliases.json",
                "src/registry/capabilities.json",
            ]
            .iter()
            .map(|s| Value::from(*s))
            .collect(),
        ),
    );
    index.insert("bundles".into(), Value::Array(bundles.clone()));

    let mut groups: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for bundle in &bundles {
        let kind = bundle.get("kind").and_then(Value::as_str).unwrap_or_default();
        let domain = bundle.get("domain").and_then(Value::as_str);
        if kind != "capability" || domain.is_none() {
            continue;
        }
        groups.entry(domain.unwrap().to_string()).or_default().push(bundle.get("id").and_then(Value::as_str).unwrap_or_default().to_string());
    }
    let domain_entries: Vec<Value> = groups
        .into_iter()
        .map(|(id, mut children)| {
            children.sort();
            let mut o = Map::new();
            o.insert("id".into(), Value::from(id));
            o.insert("kind".into(), Value::from("group"));
            o.insert(
                "children".into(),
                Value::Array(
                    children
                        .into_iter()
                        .map(|c| {
                            let mut m = Map::new();
                            m.insert("id".into(), Value::from(c));
                            Value::Object(m)
                        })
                        .collect(),
                ),
            );
            Value::Object(o)
        })
        .collect();
    let mut domains = Map::new();
    domains.insert("schemaVersion".into(), Value::from(2));
    domains.insert("generatedFrom".into(), Value::Array(vec![Value::from("src/registry/skills/index.json")]));
    domains.insert("domains".into(), Value::Array(domain_entries));

    Ok((Value::Object(index), Value::Object(domains)))
}

fn render(value: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(value).unwrap())
}

pub fn run(root: &Path, check: bool) -> bool {
    let (index, domains) = match build_skill_catalog(root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("generate-skill-catalog: {e}");
            return false;
        }
    };
    let index_text = render(&index);
    let domains_text = render(&domains);
    let bundles_len = index["bundles"].as_array().map(|a| a.len()).unwrap_or(0);
    let groups_len = domains["domains"].as_array().map(|a| a.len()).unwrap_or(0);

    if check {
        let mut drift = Vec::new();
        for (rel, expected) in [(OUT_INDEX, &index_text), (OUT_DOMAINS, &domains_text)] {
            let current = fs::read_to_string(root.join(rel)).unwrap_or_default();
            if &current != expected {
                if let Some((n, (have, want))) = current.lines().zip(expected.lines()).enumerate().find(|(_, (a, b))| a != b) {
                    eprintln!("{rel}:{}: checked in `{have}`, generated `{want}`", n + 1);
                } else {
                    eprintln!("{rel}: length differs ({} vs {} bytes)", current.len(), expected.len());
                }
                drift.push(rel);
            }
        }
        if !drift.is_empty() {
            eprintln!(
                "skill catalog drift: {} do not match their canonical sources.\nRun: cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- generate-skill-catalog",
                drift.join(", ")
            );
            return false;
        }
        println!("skill catalog: no drift ({bundles_len} bundles, {groups_len} groups)");
        return true;
    }

    for (rel, text) in [(OUT_INDEX, &index_text), (OUT_DOMAINS, &domains_text)] {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(e) = fs::write(&path, text) {
            eprintln!("generate-skill-catalog: {rel}: {e}");
            return false;
        }
    }
    println!("wrote {OUT_INDEX} ({bundles_len} bundles) and {OUT_DOMAINS} ({groups_len} groups)");
    true
}

#[cfg(test)]
mod apple_skill_tests {
    use super::*;
    use crate::generators::{codex_skill_sidecars, host_projection, refresh_local_skill_manifests};
    use regex::Regex;

    const APPLE_SKILLS: [&str; 2] = ["ios-development", "macos-development"];

    fn repository_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
    }

    #[test]
    fn apple_skills_are_public_with_workflow_scoped_tools() {
        let root = repository_root();
        let (catalog, domains) = build_skill_catalog(&root).unwrap();
        let projection = host_projection::build_projection(&root).unwrap();
        let sidecars = codex_skill_sidecars::expected_codex_sidecars(&root).unwrap();
        let engineering = domains["domains"].as_array().unwrap().iter()
            .find(|domain| domain["id"] == "engineering").unwrap();
        for id in APPLE_SKILLS {
            let skill = catalog["bundles"].as_array().unwrap().iter()
                .find(|skill| skill["id"] == id).unwrap();
            assert_eq!(skill["kind"], "capability");
            assert_eq!(skill["discoverability"], "public");
            assert!(skill["hostRequirements"].as_array().unwrap().is_empty());
            assert!(engineering["children"].as_array().unwrap().iter()
                .any(|child| child["id"] == id));
            let scoped = skill["scopedRequirementDetails"].as_array().unwrap();
            assert!(scoped.iter().any(|item| item["scope"] == "workflow:xcode-build-test"
                && item["id"] == "apple-xcode"));
            assert!(scoped.iter().any(|item| item["scope"] == "adapter:apple-build-mcp"));
            assert!(scoped.iter().all(|item| item["degradation"].as_str()
                .is_some_and(|value| !value.is_empty())));
            let host = projection["capabilities"].as_array().unwrap().iter()
                .find(|skill| skill["id"] == id).unwrap();
            assert_eq!(host["invocation"]["user"], true);
            assert_eq!(host["invocation"]["model"], true);
            let (_, text) = sidecars.iter().find(|(name, _)| name == id).unwrap();
            assert!(text.contains("allow_implicit_invocation: true"));
        }
    }

    #[test]
    fn apple_skills_resolve_references_after_standalone_copy() {
        let root = repository_root();
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_nanos();
        let temporary = std::env::temp_dir().join(format!("legion-apple-skills-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&temporary).unwrap();
        let links = Regex::new(r"\[[^\]]+\]\(([^)]+)\)").unwrap();
        for id in APPLE_SKILLS {
            let source = root.join("skills").join(id);
            let destination = temporary.join(id);
            for entry in walkdir::WalkDir::new(&source) {
                let entry = entry.unwrap();
                assert!(!entry.file_type().is_symlink(), "symlinks cannot ship in {id}");
                let target = destination.join(entry.path().strip_prefix(&source).unwrap());
                if entry.file_type().is_dir() {
                    fs::create_dir_all(&target).unwrap();
                } else {
                    fs::copy(entry.path(), &target).unwrap();
                }
            }
            let package_root = destination.canonicalize().unwrap();
            for entry in walkdir::WalkDir::new(&destination) {
                let entry = entry.unwrap();
                if entry.path().extension().and_then(|ext| ext.to_str()) != Some("md") {
                    continue;
                }
                let text = fs::read_to_string(entry.path()).unwrap();
                for capture in links.captures_iter(&text) {
                    let link = &capture[1];
                    if link.contains("://") || link.starts_with('#') {
                        continue;
                    }
                    let path = link.split('#').next().unwrap();
                    let resolved = entry.path().parent().unwrap().join(path).canonicalize()
                        .unwrap_or_else(|error| panic!("{id}: unresolved {link}: {error}"));
                    assert!(resolved.starts_with(&package_root), "{id}: link escapes bundle: {link}");
                }
            }
        }
        fs::remove_dir_all(&temporary).unwrap();
    }

    #[test]
    fn apple_tool_setup_is_self_contained_and_discoverable() {
        let root = repository_root();
        let expected = ["mobilebuildmcp", "axe", "docsetquery", "xcbeautify", "sourcery",
            "inject", "ascctl", "asc", "rocketsim", "codexmonitor", "agent-scripts"];
        for id in APPLE_SKILLS {
            let bundle = root.join("skills").join(id);
            let entry = fs::read_to_string(bundle.join("SKILL.md")).unwrap();
            assert!(entry.contains("mandatory [tool setup lifecycle]"));
            let setup = fs::read_to_string(bundle.join("references/tool-setup.md")).unwrap();
            let catalog = read_json(&bundle.join("config/tool-catalog.json")).unwrap();
            let tools = catalog["tools"].as_array().unwrap();
            assert_eq!(tools.len(), expected.len());
            for tool_id in expected {
                let matches: Vec<_> = tools.iter().filter(|tool| tool["id"] == tool_id).collect();
                assert_eq!(matches.len(), 1, "missing/duplicate setup entry {tool_id}");
                let tool = matches[0];
                for field in ["source", "scope", "useWhen", "setupRecipe", "verify", "versionPolicy"] {
                    assert!(tool[field].as_str().is_some_and(|value| !value.trim().is_empty()), "{tool_id}: {field}");
                }
                assert!(tool["source"].as_str().unwrap().starts_with("https://"));
                assert_eq!(tool["recipeReference"], format!("references/tool-setup.md#{tool_id}"));
                assert!(setup.contains(&format!("## {tool_id}\n")));
            }
            assert!(setup.contains("never replace an entire config file") || setup.contains("never\n   replace an entire config file"));
            assert!(setup.contains("do not rerun installation") || setup.contains("Do not rerun installation"));
            assert!(bundle.join("scripts/tool_preflight.py").is_file());
        }
        for path in ["config/tool-catalog.json", "scripts/tool_preflight.py", "references/tool-setup.md"] {
            assert_eq!(fs::read(root.join("skills/ios-development").join(path)).unwrap(),
                fs::read(root.join("skills/macos-development").join(path)).unwrap());
        }
    }

    #[test]
    fn apple_skill_manifests_bind_current_files_and_source_notices() {
        let root = repository_root();
        for id in APPLE_SKILLS {
            let generated = refresh_local_skill_manifests::build_local_skill_manifest(&root, id).unwrap();
            let current = read_json(&generated.manifest_path).unwrap();
            assert_eq!(current, generated.manifest);
            assert_eq!(current["licenseState"], "licensed");
            assert_eq!(current["rightsReceipt"]["sourceManifest"], "config/source-manifest.json");
            let files = current["files"].as_array().unwrap();
            for required in ["config/source-manifest.json", "references/third-party-notices.md", "evals/evals.json", "config/tool-catalog.json", "references/tool-setup.md", "scripts/tool_preflight.py"] {
                assert!(files.iter().any(|file| file["path"] == required));
            }
        }
    }
}
