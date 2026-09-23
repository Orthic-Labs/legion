//! Compact top-level YAML frontmatter parser for packaged `SKILL.md` files.
//!
//! Ported from `src/lib/skills/skill-frontmatter.mjs`.

use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

static LIST_FIELDS: &[&str] = &["operations", "effects", "hostRequirements"];
static SCALAR_FIELDS: &[&str] = &["name", "description", "kind", "capabilityClass", "discoverability", "domain"];
static KINDS: &[&str] = &["capability", "entrypoint"];
static CAPABILITY_CLASSES: &[&str] = &["domain", "workflow", "context"];
static DISCOVERABILITY: &[&str] = &["public", "explicit", "internal"];
static DOMAINS: &[&str] = &["engineering", "research", "commercial", "editorial", "design", "null"];
static OPERATIONS: &[&str] = &["route", "analyze", "diagnose", "decide", "produce", "evaluate", "execute"];
static EFFECTS: &[&str] = &["source-read", "artifact-write", "repository-write", "process-exec", "network-request"];

static TOP_LEVEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]*(.*))?$").unwrap());
static UNQUOTED_MAPPING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r":[ \t]").unwrap());
static BLOCK_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+\S").unwrap());
static LIST_ITEM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+-\s+\S").unwrap());
static LIST_ITEM_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+-\s+").unwrap());
static BLANK_OR_INDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s*$|\s+)").unwrap());

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FrontmatterValue {
    #[default]
    Empty,
    Scalar(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, Default)]
pub struct SkillFrontmatter {
    pub fields: BTreeMap<String, FrontmatterValue>,
}

impl SkillFrontmatter {
    pub fn scalar(&self, key: &str) -> Option<&str> {
        match self.fields.get(key) {
            Some(FrontmatterValue::Scalar(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn list(&self, key: &str) -> Vec<&str> {
        match self.fields.get(key) {
            Some(FrontmatterValue::List(values)) => values.iter().map(String::as_str).collect(),
            _ => vec![],
        }
    }
}

struct Block {
    key: String,
    folded: bool,
    lines: Vec<String>,
}

fn scalar_value(path: &str, key: &str, raw: &str) -> Result<String, String> {
    let text = raw.trim();
    if text.is_empty() {
        return Ok(String::new());
    }
    let quoted = (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
        || (text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2);
    if quoted {
        return Ok(text[1..text.len() - 1].to_string());
    }
    if UNQUOTED_MAPPING.is_match(text) {
        return Err(format!("{path}: {key} contains an unquoted YAML mapping delimiter"));
    }
    Ok(text.to_string())
}

/// Parse and validate the compact top-level YAML subset used by packaged `SKILL.md` files.
pub fn parse_skill_frontmatter(text: &str, path: &str) -> Result<SkillFrontmatter, String> {
    if !text.starts_with("---\n") {
        return Err(format!("{path}: missing YAML frontmatter opener"));
    }
    let end = text[4..]
        .find("\n---")
        .ok_or_else(|| format!("{path}: missing YAML frontmatter closer"))?
        + 4;
    let body = &text[4..end];
    let raw_lines: Vec<&str> = body.lines().collect();

    let mut out: BTreeMap<String, FrontmatterValue> = BTreeMap::new();
    let mut current_key: Option<String> = None;
    let mut block: Option<Block> = None;

    let finish_block = |block: &mut Option<Block>, out: &mut BTreeMap<String, FrontmatterValue>| {
        if let Some(b) = block.take() {
            let sep = if b.folded { " " } else { "\n" };
            let joined = b.lines.join(sep);
            out.insert(b.key, FrontmatterValue::Scalar(joined.trim().to_string()));
        }
    };

    for (index, line) in raw_lines.iter().enumerate() {
        if let Some(captures) = TOP_LEVEL.captures(line) {
            finish_block(&mut block, &mut out);
            let key = captures[1].to_string();
            let value = captures.get(2).map(|m| m.as_str()).unwrap_or("");
            current_key = Some(key.clone());
            if LIST_FIELDS.contains(&key.as_str()) {
                if !value.trim().is_empty() && value.trim() != "[]" {
                    return Err(format!("{path}:{}: {key} must use a YAML block list or []", index + 2));
                }
                out.insert(key, FrontmatterValue::List(vec![]));
            } else if SCALAR_FIELDS.contains(&key.as_str()) {
                let trimmed = value.trim();
                if trimmed == ">" || trimmed == "|" {
                    block = Some(Block { key, folded: trimmed == ">", lines: vec![] });
                } else {
                    let scalar = scalar_value(path, &key, value)?;
                    out.insert(key, FrontmatterValue::Scalar(scalar));
                }
            }
            continue;
        }

        if block.is_some() && BLOCK_LINE.is_match(line) {
            block.as_mut().unwrap().lines.push(line.trim().to_string());
            continue;
        }
        let list_active = current_key
            .as_deref()
            .map(|k| LIST_FIELDS.contains(&k))
            .unwrap_or(false);
        if list_active && LIST_ITEM.is_match(line) {
            let item = LIST_ITEM_PREFIX.replace(line, "").to_string();
            let key = current_key.clone().unwrap();
            let scalar = scalar_value(path, &key, &item)?;
            if let Some(FrontmatterValue::List(list)) = out.get_mut(&key) {
                list.push(scalar);
            }
            continue;
        }
        if BLANK_OR_INDENT.is_match(line) {
            continue;
        }
        return Err(format!("{path}:{}: unsupported YAML frontmatter syntax", index + 2));
    }
    finish_block(&mut block, &mut out);

    for field in ["name", "description", "kind", "discoverability", "operations", "effects", "hostRequirements"] {
        if !out.contains_key(field) {
            return Err(format!("{path}: missing canonical {field} metadata"));
        }
    }

    let frontmatter = SkillFrontmatter { fields: out };
    let kind = frontmatter.scalar("kind").unwrap_or_default();
    let capability_class = frontmatter.scalar("capabilityClass");
    if kind == "capability" && capability_class.is_none() {
        return Err(format!("{path}: capability requires capabilityClass"));
    }
    if !KINDS.contains(&kind) {
        return Err(format!("{path}: invalid kind {kind}"));
    }
    let discoverability = frontmatter.scalar("discoverability").unwrap_or_default();
    if !DISCOVERABILITY.contains(&discoverability) {
        return Err(format!("{path}: invalid discoverability {discoverability}"));
    }
    if kind == "capability" {
        let class = capability_class.unwrap_or_default();
        if !CAPABILITY_CLASSES.contains(&class) {
            return Err(format!("{path}: invalid capabilityClass {class}"));
        }
    }
    if kind == "entrypoint" && capability_class.is_some() {
        return Err(format!("{path}: entrypoint cannot declare capabilityClass"));
    }
    if let Some(domain) = frontmatter.scalar("domain") {
        if !domain.is_empty() && !DOMAINS.contains(&domain) {
            return Err(format!("{path}: invalid optional domain {domain}"));
        }
    }
    for (field, vocabulary) in [("operations", OPERATIONS), ("effects", EFFECTS)] {
        let values = frontmatter.list(field);
        let unique: HashSet<&str> = values.iter().copied().collect();
        if unique.len() != values.len() {
            return Err(format!("{path}: duplicate {field} value"));
        }
        for value in &values {
            if !vocabulary.contains(value) {
                return Err(format!("{path}: invalid {field} value {value}"));
            }
        }
    }
    let host_requirements = frontmatter.list("hostRequirements");
    let unique: HashSet<&str> = host_requirements.iter().copied().collect();
    if unique.len() != host_requirements.len() {
        return Err(format!("{path}: duplicate hostRequirements value"));
    }

    Ok(frontmatter)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(extra: &str) -> String {
        format!(
            "---\nname: qa\ndescription: Runs QA\nkind: capability\ncapabilityClass: workflow\ndiscoverability: public\noperations:\n  - execute\neffects:\n  - process-exec\nhostRequirements:\n  - browser\n{extra}\n---\nbody\n"
        )
    }

    #[test]
    fn parses_valid_frontmatter() {
        let text = sample("");
        let fm = parse_skill_frontmatter(&text, "SKILL.md").unwrap();
        assert_eq!(fm.scalar("name"), Some("qa"));
        assert_eq!(fm.list("operations"), vec!["execute"]);
        assert_eq!(fm.list("hostRequirements"), vec!["browser"]);
    }

    #[test]
    fn rejects_missing_opener() {
        assert!(parse_skill_frontmatter("name: qa\n---\n", "SKILL.md").is_err());
    }

    #[test]
    fn rejects_missing_field() {
        let text = "---\nname: qa\n---\nbody\n";
        let err = parse_skill_frontmatter(text, "SKILL.md").unwrap_err();
        assert!(err.contains("missing canonical"));
    }

    #[test]
    fn rejects_duplicate_operations() {
        let text = "---\nname: qa\ndescription: d\nkind: capability\ncapabilityClass: workflow\ndiscoverability: public\noperations:\n  - execute\n  - execute\neffects: []\nhostRequirements: []\n---\n";
        let err = parse_skill_frontmatter(text, "SKILL.md").unwrap_err();
        assert!(err.contains("duplicate operations"));
    }

    #[test]
    fn rejects_entrypoint_with_capability_class() {
        let text = "---\nname: qa\ndescription: d\nkind: entrypoint\ncapabilityClass: workflow\ndiscoverability: public\noperations: []\neffects: []\nhostRequirements: []\n---\n";
        let err = parse_skill_frontmatter(text, "SKILL.md").unwrap_err();
        assert!(err.contains("entrypoint cannot declare capabilityClass"));
    }

    #[test]
    fn accepts_empty_lists() {
        let text = "---\nname: qa\ndescription: d\nkind: entrypoint\ndiscoverability: public\noperations: []\neffects: []\nhostRequirements: []\n---\n";
        let fm = parse_skill_frontmatter(text, "SKILL.md").unwrap();
        assert!(fm.list("operations").is_empty());
    }
}
