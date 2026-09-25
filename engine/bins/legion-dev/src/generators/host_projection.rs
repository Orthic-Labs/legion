//! Port of `scripts/generate-host-projection.mjs`.

use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

use crate::shared::capabilities::load_capability_registry;
use super::host_adapters::host_adapters;
use crate::shared::route_resources::scoped_requirement_details;
use crate::shared::skill_frontmatter::parse_skill_frontmatter_map as parse_skill_frontmatter;

const OUT: &str = "src/registry/host-projection.json";
const SUPPORT_OUT: &str = "references/generated/support.md";

/// Faithful port of the script's local `rosterFrontmatter(text)` (distinct
/// from — and lighter than — `src/lib/roster/index.mjs`'s frontmatter
/// parsing; only `description`/`modelTier` are read here).
fn roster_frontmatter(text: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let normalized = text.replace("\r\n", "\n");
    if !normalized.starts_with("---\n") {
        return out;
    }
    let end = match normalized[4..].find("\n---") {
        Some(i) => 4 + i,
        None => return out,
    };
    for line in normalized[4..end].split('\n') {
        // /^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/
        let bytes = line.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        let first = bytes[0] as char;
        if !(first.is_ascii_alphabetic() || first == '_') {
            continue;
        }
        let mut i = 1;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                i += 1;
            } else {
                break;
            }
        }
        if i >= bytes.len() || bytes[i] as char != ':' {
            continue;
        }
        let key = line[..i].to_string();
        let value = line[i + 1..].trim();
        let unquoted = if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            value[1..value.len() - 1].to_string()
        } else {
            value.to_string()
        };
        out.insert(key, unquoted);
    }
    out
}

fn requirement_details(registry: &Value, ids: &[String]) -> Result<Vec<Value>, String> {
    ids.iter()
        .map(|id| {
            let entry = registry.get("capabilities").and_then(|c| c.get(id));
            let entry = match entry {
                Some(e) if !e.is_null() => e,
                _ => return Err(format!("skills declare host requirement absent from registry: {id}")),
            };
            let mut out = Map::new();
            out.insert("id".into(), Value::from(id.clone()));
            out.insert("kind".into(), entry.get("kind").cloned().unwrap_or(Value::Null));
            out.insert("summary".into(), entry.get("summary").cloned().unwrap_or(Value::Null));
            out.insert("degradation".into(), entry.get("degradation").cloned().unwrap_or(Value::Null));
            out.insert("remedy".into(), entry.get("remedy").cloned().unwrap_or(Value::Null));
            out.insert("probe".into(), entry.get("probe").cloned().unwrap_or(Value::Null));
            Ok(Value::Object(out))
        })
        .collect()
}

pub fn build_projection(root: &Path) -> Result<Value, String> {
    let skills_dir = root.join("skills");
    let registry = load_capability_registry(root)?;

    let mut skill_ids: Vec<String> = fs::read_dir(&skills_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|id| skills_dir.join(id).join("SKILL.md").is_file())
        .collect();
    skill_ids.sort();

    let mut capabilities = Vec::new();
    for id in &skill_ids {
        let rel_path = format!("skills/{id}/SKILL.md");
        let text = fs::read_to_string(root.join(&rel_path)).map_err(|e| format!("{rel_path}: {e}"))?;
        let fm = parse_skill_frontmatter(&text, &rel_path)?;
        let kind = fm.get("kind").and_then(Value::as_str).unwrap_or("capability").to_string();
        let discoverability = fm.get("discoverability").and_then(Value::as_str).unwrap_or("public").to_string();
        let public_capability = kind == "capability" && discoverability == "public";
        let (inv_user, inv_model) = match discoverability.as_str() {
            "public" => (true, true),
            "explicit" => (true, false),
            _ => (false, false),
        };
        let domain = fm.get("domain").and_then(Value::as_str).filter(|s| *s != "null" && !s.is_empty()).map(Value::from).unwrap_or(Value::Null);
        let host_requirements: Vec<String> = fm
            .get("hostRequirements")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let mut cap = Map::new();
        cap.insert("id".into(), Value::from(id.clone()));
        cap.insert("name".into(), fm.get("name").cloned().unwrap_or_else(|| Value::from(id.clone())));
        cap.insert("description".into(), fm.get("description").cloned().unwrap_or_else(|| Value::from("")));
        cap.insert("kind".into(), Value::from(if public_capability { "domain-capability" } else { "entrypoint" }));
        cap.insert("discoverability".into(), Value::from(if public_capability { "public".to_string() } else { discoverability.clone() }));
        let mut invocation = Map::new();
        invocation.insert("user".into(), Value::from(inv_user));
        invocation.insert("model".into(), Value::from(inv_model));
        cap.insert("invocation".into(), Value::Object(invocation));
        cap.insert("domain".into(), domain);
        cap.insert("hostRequirements".into(), Value::Array(host_requirements.iter().cloned().map(Value::from).collect()));
        cap.insert("hostRequirementDetails".into(), Value::Array(requirement_details(&registry, &host_requirements)?));
        cap.insert(
            "scopedRequirements".into(),
            Value::Array(scoped_requirement_details(&skills_dir.join(id), &registry, id)?),
        );
        cap.insert("source".into(), Value::from(rel_path));
        capabilities.push(Value::Object(cap));
    }

    let roster_dir = root.join("src/roster");
    let mut roster_files: Vec<String> = fs::read_dir(&roster_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|f| f.ends_with(".md") && f != "README.md")
        .collect();
    roster_files.sort();
    let roles: Vec<Value> = roster_files
        .iter()
        .map(|f| {
            let rel = format!("src/roster/{f}");
            let text = fs::read_to_string(root.join(&rel)).unwrap_or_default();
            let fm = roster_frontmatter(&text);
            let mut role = Map::new();
            role.insert("id".into(), Value::from(f.trim_end_matches(".md")));
            role.insert("description".into(), Value::from(fm.get("description").cloned().unwrap_or_default()));
            role.insert(
                "modelTier".into(),
                fm.get("modelTier").map(|s| Value::from(s.clone())).unwrap_or(Value::Null),
            );
            role.insert("source".into(), Value::from(rel));
            Value::Object(role)
        })
        .collect();

    let model_tiers_doc: Value = serde_json::from_str(
        &fs::read_to_string(root.join("src/config/model-tiers.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let model_tiers = model_tiers_doc.get("tiers").cloned().unwrap_or(Value::Null);

    let mut host_capabilities: Vec<Value> = registry
        .get("capabilities")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(id, value)| {
                    let degradation = value
                        .get("degradation")
                        .filter(|v| !v.is_null())
                        .or_else(|| value.get("degrades"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    let mut o = Map::new();
                    o.insert("id".into(), Value::from(id.clone()));
                    o.insert("degradation".into(), degradation);
                    Value::Object(o)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    host_capabilities.sort_by(|a, b| a["id"].as_str().unwrap_or_default().cmp(b["id"].as_str().unwrap_or_default()));

    let mut reference_classes: Vec<String> = registry
        .get("classes")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    reference_classes.sort();

    let harnesses: Vec<Value> = host_adapters()
        .iter()
        .map(|adapter| {
            let mut fidelity = Map::new();
            fidelity.insert("instructions".into(), Value::from(adapter.surfaces[0].1.fidelity));
            fidelity.insert("skillDiscovery".into(), Value::from(adapter.surfaces[1].1.fidelity));
            fidelity.insert("authorityAgents".into(), Value::from(adapter.surfaces[2].1.fidelity));
            fidelity.insert("mcp".into(), Value::from(adapter.surfaces[3].1.fidelity));
            fidelity.insert("guardEnforcement".into(), Value::from(adapter.surfaces[4].1.fidelity));
            let mut mechanisms = Map::new();
            for (name, surface) in &adapter.surfaces {
                mechanisms.insert((*name).into(), Value::from(surface.mechanism_kind));
            }
            let mut o = Map::new();
            o.insert("id".into(), Value::from(adapter.id));
            o.insert("installOwner".into(), Value::from(adapter.install_owner));
            o.insert("fidelity".into(), Value::Object(fidelity));
            o.insert("mechanisms".into(), Value::Object(mechanisms));
            Value::Object(o)
        })
        .collect();

    let mut out = Map::new();
    out.insert("schemaVersion".into(), Value::from(1));
    out.insert("kind".into(), Value::from("legion-host-projection"));
    out.insert(
        "generatedFrom".into(),
        Value::Array(
            [
                "skills/*/SKILL.md",
                "skills/*/references/route-resources.json",
                "src/roster/*.md",
                "src/config/model-tiers.json",
                "src/registry/capabilities.json",
            ]
            .iter()
            .map(|s| Value::from(*s))
            .collect(),
        ),
    );
    out.insert("capabilities".into(), Value::Array(capabilities));
    out.insert("roles".into(), Value::Array(roles));
    out.insert("modelTiers".into(), model_tiers);
    out.insert("hostCapabilities".into(), Value::Array(host_capabilities));
    out.insert("referenceClasses".into(), Value::Array(reference_classes.into_iter().map(Value::from).collect()));
    out.insert("harnesses".into(), Value::Array(harnesses));
    Ok(Value::Object(out))
}

pub fn render_harness_support(projection: &Value) -> String {
    let mut lines = vec![
        "# Generated host support matrix".to_string(),
        String::new(),
        "Generated from registered host adapters. Values describe implemented projection fidelity, not aspirational product parity.".to_string(),
        String::new(),
        "| Host | Install owner | Instructions | Skills | Agents | MCP | Hooks | Skills mechanism | MCP mechanism |".to_string(),
        "|---|---|---|---|---|---|---|---|---|".to_string(),
    ];
    if let Some(harnesses) = projection.get("harnesses").and_then(Value::as_array) {
        for h in harnesses {
            let s = |p: &str| h["fidelity"][p].as_str().unwrap_or_default();
            lines.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                h["id"].as_str().unwrap_or_default(),
                h["installOwner"].as_str().unwrap_or_default(),
                s("instructions"),
                s("skillDiscovery"),
                s("authorityAgents"),
                s("mcp"),
                s("guardEnforcement"),
                h["mechanisms"]["skills"].as_str().unwrap_or_default(),
                h["mechanisms"]["mcp"].as_str().unwrap_or_default(),
            ));
        }
    }
    format!("{}\n", lines.join("\n"))
}

pub fn run(root: &Path, check: bool) -> bool {
    let projection = match build_projection(root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("generate-host-projection: {e}");
            return false;
        }
    };
    let rendered = format!("{}\n", serde_json::to_string_pretty(&projection).unwrap());
    let support = render_harness_support(&projection);
    let target = root.join(OUT);
    let support_target = root.join(SUPPORT_OUT);

    if check {
        let current = fs::read_to_string(&target).unwrap_or_default();
        let current_support = fs::read_to_string(&support_target).unwrap_or_default();
        if current != rendered || current_support != support {
            eprintln!(
                "host projection drift: {OUT} or {SUPPORT_OUT} does not match canonical sources.\nRun: node scripts/generate-host-projection.mjs"
            );
            return false;
        }
        println!("host projection: no drift");
        return true;
    }

    if let Some(parent) = target.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Some(parent) = support_target.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::write(&target, &rendered).is_err() || fs::write(&support_target, &support).is_err() {
        eprintln!("generate-host-projection: failed to write output");
        return false;
    }
    let capabilities_len = projection["capabilities"].as_array().map(|a| a.len()).unwrap_or(0);
    let roles_len = projection["roles"].as_array().map(|a| a.len()).unwrap_or(0);
    let harnesses_len = projection["harnesses"].as_array().map(|a| a.len()).unwrap_or(0);
    println!("wrote {OUT} ({capabilities_len} capabilities, {roles_len} roles, {harnesses_len} harnesses)");
    true
}
