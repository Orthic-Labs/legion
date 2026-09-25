//! Port of `src/lib/roster/index.mjs`.
//!
//! Not read by `generate-host-projection.mjs` (which parses `src/roster/*.md`
//! with its own lighter-weight local `rosterFrontmatter`, ported inline in
//! `host_projection.rs`); ported here for other T2 callers per the brief.

use std::fs;
use std::path::{Path, PathBuf};

pub const ROLE_IDS: &[&str] = &["sage", "alchemist", "oracle"];
const MODEL_TIERS: &[&str] = &["frontier-judgment", "balanced-executor", "mechanical-cheap"];
const PROJECTION_SECTIONS: &[&str] = &[
    "Purpose", "Triggers", "Routes", "Capabilities", "Inputs", "Outputs", "Boundaries", "Handoffs",
    "Evidence rules", "Model policy",
];

fn route_method(id: &str) -> &'static str {
    match id {
        "sage" => "doctrine/sage.md",
        "alchemist" => "doctrine/alchemist.md",
        "oracle" => "doctrine/oracle.md",
        _ => "",
    }
}

pub struct RosterRole {
    pub id: String,
    pub path: PathBuf,
    pub name: String,
    pub description: String,
    pub model_tier: String,
    pub delegation_tiers: String,
    pub body: String,
}

fn parse_frontmatter(text: &str, path: &Path) -> Result<(std::collections::BTreeMap<String, String>, String), String> {
    if !text.starts_with("---") {
        return Err(format!("{}: missing frontmatter", path.display()));
    }
    let normalized = text.replace("\r\n", "\n");
    if !normalized.starts_with("---\n") {
        return Err(format!("{}: missing frontmatter", path.display()));
    }
    let end = normalized[4..].find("\n---\n").map(|i| i + 4);
    let end = match end {
        Some(e) => e,
        None => return Err(format!("{}: missing frontmatter", path.display())),
    };
    let fm_block = &normalized[4..end];
    let mut values = std::collections::BTreeMap::new();
    for line in fm_block.split('\n') {
        if let Some(idx) = line.find(':') {
            if idx > 0 {
                values.insert(line[..idx].trim().to_string(), line[idx + 1..].trim().to_string());
            }
        }
    }
    let body = normalized[end + 5..].trim().to_string();
    Ok((values, body))
}

fn section(body: &str, name: &str) -> Option<String> {
    let heading = format!("## {name}");
    let start_line = body.lines().position(|l| l.trim_eq_heading(&heading))?;
    let lines: Vec<&str> = body.lines().collect();
    let mut end_line = lines.len();
    for (i, l) in lines.iter().enumerate().skip(start_line + 1) {
        if l.starts_with("## ") {
            end_line = i;
            break;
        }
    }
    let content = lines[start_line + 1..end_line].join("\n");
    Some(format!("## {}\n\n{}", name, content.trim()))
}

trait TrimEqHeading {
    fn trim_eq_heading(&self, heading: &str) -> bool;
}
impl TrimEqHeading for &str {
    fn trim_eq_heading(&self, heading: &str) -> bool {
        // case-insensitive match against "## Name" with optional trailing spaces (mirrors /^##\s+name\s*$/mi over one line)
        self.trim_end().eq_ignore_ascii_case(heading)
    }
}

pub fn roster_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    if !ROLE_IDS.contains(&id) {
        return Err(format!("unknown roster role: {id}"));
    }
    Ok(root.join("src/roster").join(format!("{id}.md")))
}

pub fn load_roster_role(root: &Path, id: &str) -> Result<RosterRole, String> {
    let path = roster_path(root, id)?;
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (values, body) = parse_frontmatter(&text, &path)?;
    let name = values.get("name").cloned().unwrap_or_default();
    if name != id {
        return Err(format!("{}: expected name {id}", path.display()));
    }
    let description = values.get("description").cloned().unwrap_or_default();
    if !description.contains("Dispatch") {
        return Err(format!("{}: description must contain Dispatch", path.display()));
    }
    let model_tier = values.get("modelTier").cloned().unwrap_or_default();
    if !MODEL_TIERS.contains(&model_tier.as_str()) {
        return Err(format!("{}: unsupported modelTier {}", path.display(), if model_tier.is_empty() { "<missing>" } else { &model_tier }));
    }
    let delegation_tiers = values.get("delegationTiers").cloned().unwrap_or_default();
    Ok(RosterRole { id: id.to_string(), path, name, description, model_tier, delegation_tiers, body })
}

pub fn roster_roles(root: &Path) -> Result<Vec<RosterRole>, String> {
    ROLE_IDS.iter().map(|id| load_roster_role(root, id)).collect()
}

pub fn role_projection(root: &Path, id: &str) -> Result<String, String> {
    let role = load_roster_role(root, id)?;
    let sections: Vec<String> = PROJECTION_SECTIONS.iter().filter_map(|name| section(&role.body, name)).collect();
    let mut name_cap = role.name.clone();
    if let Some(c) = name_cap.get_mut(0..1) {
        c.make_ascii_uppercase();
    }
    let mut lines = vec![
        "---".to_string(),
        format!("name: {}", role.name),
        format!("description: {}", role.description),
        "---".to_string(),
        String::new(),
        format!("# {name_cap} — Legion role"),
        String::new(),
        format!("Model tier: `{}`. Host resolves a compatible provider/model; roster source is vendor-neutral.", role.model_tier),
        String::new(),
        format!("Route method: `{}`.", route_method(id)),
        String::new(),
    ];
    lines.extend(sections);
    lines.push(String::new());
    Ok(lines.join("\n"))
}

pub fn low_fidelity_projection(root: &Path) -> Result<String, String> {
    let roles = roster_roles(root)?;
    let mut lines = vec!["# Legion authority context".to_string(), String::new()];
    for role in &roles {
        lines.push(format!("- **{}** — {} Model tier: `{}`.", role.name, role.description, role.model_tier));
    }
    lines.push("- **Covenant seat** — doctrine-only advisory review seat; not an authority.".to_string());
    lines.push(String::new());
    lines.push("Use Legion routing. Do not edit generated harness files; rerun `legion bind --write`.".to_string());
    Ok(lines.join("\n"))
}
