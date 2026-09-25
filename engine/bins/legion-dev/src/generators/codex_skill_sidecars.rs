//! Port of `scripts/generate-codex-skill-sidecars.mjs`.

use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

use crate::shared::skill_frontmatter::parse_skill_frontmatter_map as parse_skill_frontmatter;

fn display_name(id: &str) -> String {
    id.split('-')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}

pub fn render_codex_skill_sidecar(id: &str, metadata: &Map<String, Value>) -> String {
    let implicit = metadata.get("discoverability").and_then(Value::as_str) == Some("public");
    let description_raw = metadata.get("description").and_then(Value::as_str).unwrap_or_default();
    let description = description_raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let lines = vec![
        "interface:".to_string(),
        format!("  display_name: {}", yaml_string(&display_name(id))),
        format!("  short_description: {}", yaml_string(&description)),
        format!(
            "  default_prompt: {}",
            yaml_string(&format!("Use ${id} when this request matches: {description}"))
        ),
        "policy:".to_string(),
        format!("  allow_implicit_invocation: {implicit}"),
        String::new(),
    ];
    lines.join("\n")
}

/// Ordered `(id, text)` pairs, sorted by id, matching `expectedCodexSidecars`.
pub fn expected_codex_sidecars(root: &Path) -> Result<Vec<(String, String)>, String> {
    let skills_root = root.join("skills");
    let mut ids: Vec<String> = fs::read_dir(&skills_root)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    ids.sort();

    let mut out = Vec::new();
    for id in ids {
        let skill_path = skills_root.join(&id).join("SKILL.md");
        if !skill_path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&skill_path).map_err(|e| e.to_string())?;
        let metadata = parse_skill_frontmatter(&text, &format!("skills/{id}/SKILL.md"))?;
        if metadata.get("discoverability").and_then(Value::as_str) == Some("internal") {
            continue;
        }
        let rendered = render_codex_skill_sidecar(&id, &metadata);
        out.push((id, rendered));
    }
    Ok(out)
}

const CODEX_DESCRIPTION: &str = "Legion — orchestration for AI-assisted engineering. Legion selects capabilities & attaches Sage, Alchemist, or Oracle where required; Arcane shapes cognitive processing & response policy; Guard enforcement is host-dependent.";

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn expected_codex_plugin(root: &Path) -> Result<Value, String> {
    let claude = read_json(&root.join(".claude-plugin/plugin.json"))?;
    let author = match claude.get("author") {
        Some(Value::Object(o)) => o.get("name").cloned().unwrap_or(Value::Null),
        Some(v) => v.clone(),
        None => Value::Null,
    };
    let display_name_val = claude
        .get("displayName")
        .cloned()
        .unwrap_or_else(|| Value::from(display_name(claude.get("name").and_then(Value::as_str).unwrap_or_default())));

    let mut interface = Map::new();
    interface.insert("displayName".into(), display_name_val);
    interface.insert("category".into(), Value::from("Developer Tools"));
    interface.insert(
        "capabilities".into(),
        Value::Array(
            ["Legion orchestration", "Arcane cognitive policy", "Covenant review"]
                .iter()
                .map(|s| Value::from(*s))
                .collect(),
        ),
    );
    interface.insert(
        "defaultPrompt".into(),
        Value::from("Use Legion authority routing for repository or system-state changes."),
    );

    let mut out = Map::new();
    out.insert("name".into(), claude.get("name").cloned().unwrap_or(Value::Null));
    out.insert("version".into(), claude.get("version").cloned().unwrap_or(Value::Null));
    out.insert("author".into(), author);
    out.insert("description".into(), Value::from(CODEX_DESCRIPTION));
    out.insert("license".into(), claude.get("license").cloned().unwrap_or(Value::Null));
    out.insert("interface".into(), Value::Object(interface));
    Ok(Value::Object(out))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(a) => Value::Array(a.iter().map(canonicalize).collect()),
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            let mut m = Map::new();
            for k in keys {
                m.insert(k.clone(), canonicalize(&o[k]));
            }
            Value::Object(m)
        }
        other => other.clone(),
    }
}

fn same_json(left: Option<&Value>, right: &Value) -> bool {
    let l = left.map(canonicalize).unwrap_or(Value::Null);
    let r = canonicalize(right);
    serde_json::to_string(&l).unwrap() == serde_json::to_string(&r).unwrap()
}

fn existing_sidecar_ids(root: &Path) -> Vec<String> {
    let skills_root = root.join("skills");
    fs::read_dir(&skills_root)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|id| skills_root.join(id).join("agents/openai.yaml").is_file())
        .collect()
}

pub fn run(root: &Path, check: bool) -> bool {
    let expected = match expected_codex_sidecars(root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("generate-codex-skill-sidecars: {e}");
            return false;
        }
    };
    let expected_map: std::collections::HashMap<&str, &str> = expected.iter().map(|(id, t)| (id.as_str(), t.as_str())).collect();
    let mut drift: Vec<String> = Vec::new();

    let expected_plugin = match expected_codex_plugin(root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("generate-codex-skill-sidecars: {e}");
            return false;
        }
    };
    let plugin_path = root.join(".codex-plugin/plugin.json");
    let current_plugin: Option<Value> = fs::read_to_string(&plugin_path).ok().and_then(|s| serde_json::from_str(&s).ok());
    if !same_json(current_plugin.as_ref(), &expected_plugin) && check {
        drift.push(".codex-plugin/plugin.json".to_string());
    }

    for (id, text) in &expected {
        let path = root.join("skills").join(id).join("agents/openai.yaml");
        let current = fs::read_to_string(&path).unwrap_or_default();
        if &current == text {
            continue;
        }
        if check {
            drift.push(format!("skills/{id}/agents/openai.yaml"));
        } else {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(e) = fs::write(&path, text) {
                eprintln!("generate-codex-skill-sidecars: {e}");
                return false;
            }
        }
    }
    for id in existing_sidecar_ids(root) {
        if expected_map.contains_key(id.as_str()) {
            continue;
        }
        let path = root.join("skills").join(&id).join("agents/openai.yaml");
        if check {
            drift.push(format!("skills/{id}/agents/openai.yaml"));
        } else {
            let _ = fs::remove_file(&path);
        }
    }

    if !check {
        if let Some(parent) = plugin_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let text = format!("{}\n", serde_json::to_string_pretty(&expected_plugin).unwrap());
        if let Err(e) = fs::write(&plugin_path, text) {
            eprintln!("generate-codex-skill-sidecars: {e}");
            return false;
        }
    }

    if !drift.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<&String> = drift.iter().filter(|p| seen.insert((*p).clone())).collect();
        eprintln!(
            "Codex skill sidecar drift:\n{}",
            unique.iter().map(|p| format!("- {p}")).collect::<Vec<_>>().join("\n")
        );
        return false;
    }

    if check {
        println!("Codex skill sidecars: no drift ({})", expected.len());
    } else {
        println!("wrote {} Codex skill sidecars", expected.len());
    }
    true
}
