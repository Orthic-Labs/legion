// Port of `src/lib/skills/skill-frontmatter.mjs` (== `scripts/lib/skill-frontmatter.mjs`,
// a re-export in JS). Parses & validates the compact top-level YAML subset
// used by packaged SKILL.md files.

use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashSet;

const SCALAR_FIELDS: &[&str] = &[
    "name",
    "description",
    "kind",
    "capabilityClass",
    "discoverability",
    "domain",
];
const LIST_FIELDS: &[&str] = &["operations", "effects", "hostRequirements"];
const KINDS: &[&str] = &["capability", "entrypoint"];
const CAPABILITY_CLASSES: &[&str] = &["domain", "workflow", "context"];
const DISCOVERABILITY: &[&str] = &["public", "explicit", "internal"];
const DOMAINS: &[&str] = &["engineering", "research", "commercial", "editorial", "design", "null"];
const OPERATIONS: &[&str] = &["route", "analyze", "diagnose", "decide", "produce", "evaluate", "execute"];
const EFFECTS: &[&str] = &[
    "source-read",
    "artifact-write",
    "repository-write",
    "process-exec",
    "network-request",
];

#[derive(Default, Clone)]
pub struct Frontmatter {
    pub name: String,
    pub description: String,
    pub kind: String,
    pub capability_class: Option<String>,
    pub discoverability: String,
    pub domain: Option<String>,
    pub operations: Vec<String>,
    pub effects: Vec<String>,
    pub host_requirements: Vec<String>,
}

impl Frontmatter {
    /// Render as the JSON-object shape produced by the JS
    /// `parseSkillFrontmatter`, for callers that consume it as a `Value` map
    /// rather than typed fields.
    pub fn as_value(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("name".into(), Value::from(self.name.clone()));
        out.insert("description".into(), Value::from(self.description.clone()));
        out.insert("kind".into(), Value::from(self.kind.clone()));
        if let Some(cc) = &self.capability_class {
            out.insert("capabilityClass".into(), Value::from(cc.clone()));
        }
        out.insert("discoverability".into(), Value::from(self.discoverability.clone()));
        if let Some(d) = &self.domain {
            out.insert("domain".into(), Value::from(d.clone()));
        }
        out.insert(
            "operations".into(),
            Value::Array(self.operations.iter().cloned().map(Value::from).collect()),
        );
        out.insert(
            "effects".into(),
            Value::Array(self.effects.iter().cloned().map(Value::from).collect()),
        );
        out.insert(
            "hostRequirements".into(),
            Value::Array(self.host_requirements.iter().cloned().map(Value::from).collect()),
        );
        out
    }
}

enum Field {
    Scalar(String),
    List(Vec<String>),
}

fn scalar(value: &str, path: &str, key: &str) -> Result<String, String> {
    let text = value.trim();
    if text.is_empty() {
        return Ok(String::new());
    }
    let quoted = (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
        || (text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2);
    if quoted {
        return Ok(text[1..text.len() - 1].to_string());
    }
    if Regex::new(r":[ \t]").unwrap().is_match(text) {
        return Err(format!("{path}: {key} contains an unquoted YAML mapping delimiter"));
    }
    Ok(text.to_string())
}

pub fn parse_skill_frontmatter(text: &str, path: &str) -> Result<Frontmatter, String> {
    if !text.starts_with("---\n") {
        return Err(format!("{path}: missing YAML frontmatter opener"));
    }
    let closer_idx = text[4..].find("\n---").map(|i| i + 4);
    let end = closer_idx.ok_or_else(|| format!("{path}: missing YAML frontmatter closer"))?;
    let body = &text[4..end];
    let lines: Vec<&str> = body.split(['\n']).collect();
    // Handle CRLF the same as the JS `split(/\r?\n/)`: strip trailing \r per line.
    let lines: Vec<String> = lines.iter().map(|l| l.trim_end_matches('\r').to_string()).collect();

    let mut out: std::collections::HashMap<String, Field> = std::collections::HashMap::new();
    let mut key: Option<String> = None;
    let mut block: Option<(String, bool, Vec<String>)> = None; // (key, folded, lines)

    let top_re = Regex::new(r"^([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]*(.*))?$").unwrap();
    let list_field_set: HashSet<&str> = LIST_FIELDS.iter().copied().collect();
    let scalar_field_set: HashSet<&str> = SCALAR_FIELDS.iter().copied().collect();

    let finish_block = |block: &mut Option<(String, bool, Vec<String>)>,
                         out: &mut std::collections::HashMap<String, Field>| {
        if let Some((k, folded, lines)) = block.take() {
            let sep = if folded { " " } else { "\n" };
            out.insert(k, Field::Scalar(lines.join(sep).trim().to_string()));
        }
    };

    for (index, line) in lines.iter().enumerate() {
        if let Some(caps) = top_re.captures(line) {
            finish_block(&mut block, &mut out);
            let k = caps[1].to_string();
            let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            key = Some(k.clone());
            if list_field_set.contains(k.as_str()) {
                let v = value.trim();
                if !v.is_empty() && v != "[]" {
                    return Err(format!("{path}:{}: {k} must use a YAML block list or []", index + 2));
                }
                out.insert(k.clone(), Field::List(Vec::new()));
            } else if scalar_field_set.contains(k.as_str()) {
                let v = value.trim();
                if v == ">" || v == "|" {
                    block = Some((k.clone(), v == ">", Vec::new()));
                } else {
                    out.insert(k.clone(), Field::Scalar(scalar(value, path, &k)?));
                }
            }
            continue;
        }

        if let Some((_, _, block_lines)) = &mut block {
            if Regex::new(r"^\s+\S").unwrap().is_match(line) {
                block_lines.push(line.trim().to_string());
                continue;
            }
        }
        if let Some(k) = &key {
            if list_field_set.contains(k.as_str()) && Regex::new(r"^\s+-\s+\S").unwrap().is_match(line) {
                let item_text = Regex::new(r"^\s+-\s+").unwrap().replace(line, "");
                let item = scalar(&item_text, path, k)?;
                if let Some(Field::List(items)) = out.get_mut(k) {
                    items.push(item);
                }
                continue;
            }
        }
        if Regex::new(r"^\s*$").unwrap().is_match(line) || Regex::new(r"^\s+").unwrap().is_match(line) {
            continue;
        }
        return Err(format!("{path}:{}: unsupported YAML frontmatter syntax", index + 2));
    }
    finish_block(&mut block, &mut out);

    for field in [
        "name",
        "description",
        "kind",
        "discoverability",
        "operations",
        "effects",
        "hostRequirements",
    ] {
        if !out.contains_key(field) {
            return Err(format!("{path}: missing canonical {field} metadata"));
        }
    }

    let get_scalar = |m: &std::collections::HashMap<String, Field>, k: &str| -> String {
        match m.get(k) {
            Some(Field::Scalar(s)) => s.clone(),
            _ => String::new(),
        }
    };
    let get_list = |m: &std::collections::HashMap<String, Field>, k: &str| -> Vec<String> {
        match m.get(k) {
            Some(Field::List(v)) => v.clone(),
            _ => Vec::new(),
        }
    };

    let kind = get_scalar(&out, "kind");
    let capability_class_raw = out.get("capabilityClass").map(|_| get_scalar(&out, "capabilityClass"));
    if kind == "capability" && capability_class_raw.as_deref().unwrap_or("").is_empty() {
        return Err(format!("{path}: capability requires capabilityClass"));
    }
    if !KINDS.contains(&kind.as_str()) {
        return Err(format!("{path}: invalid kind {kind}"));
    }
    let discoverability = get_scalar(&out, "discoverability");
    if !DISCOVERABILITY.contains(&discoverability.as_str()) {
        return Err(format!("{path}: invalid discoverability {discoverability}"));
    }
    if kind == "capability" {
        let cc = capability_class_raw.clone().unwrap_or_default();
        if !CAPABILITY_CLASSES.contains(&cc.as_str()) {
            return Err(format!("{path}: invalid capabilityClass {cc}"));
        }
    }
    if kind == "entrypoint" && capability_class_raw.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        return Err(format!("{path}: entrypoint cannot declare capabilityClass"));
    }
    let domain = out.get("domain").map(|_| get_scalar(&out, "domain"));
    if let Some(d) = &domain {
        if !d.is_empty() && !DOMAINS.contains(&d.as_str()) {
            return Err(format!("{path}: invalid optional domain {d}"));
        }
    }
    let operations = get_list(&out, "operations");
    let effects = get_list(&out, "effects");
    let host_requirements = get_list(&out, "hostRequirements");
    for (field_name, values, vocabulary) in [
        ("operations", &operations, OPERATIONS),
        ("effects", &effects, EFFECTS),
    ] {
        let set: HashSet<&String> = values.iter().collect();
        if set.len() != values.len() {
            return Err(format!("{path}: duplicate {field_name} value"));
        }
        for value in values {
            if !vocabulary.contains(&value.as_str()) {
                return Err(format!("{path}: invalid {field_name} value {value}"));
            }
        }
    }
    let hr_set: HashSet<&String> = host_requirements.iter().collect();
    if hr_set.len() != host_requirements.len() {
        return Err(format!("{path}: duplicate hostRequirements value"));
    }

    Ok(Frontmatter {
        name: get_scalar(&out, "name"),
        description: get_scalar(&out, "description"),
        kind,
        capability_class: capability_class_raw.filter(|s| !s.is_empty()),
        discoverability,
        domain: domain.filter(|s| !s.is_empty()),
        operations,
        effects,
        host_requirements,
    })
}

/// `parseSkillFrontmatter` in its JSON-object shape, for generator callers.
pub fn parse_skill_frontmatter_map(text: &str, path: &str) -> Result<Map<String, Value>, String> {
    parse_skill_frontmatter(text, path).map(|f| f.as_value())
}
