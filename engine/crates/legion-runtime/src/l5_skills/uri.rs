//! Skill package URI parsing, ported from `src/lib/skills/uri.mjs`.

use regex::Regex;
use std::sync::LazyLock;

static URI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^legion-skill://([a-z0-9-]+)/([^?#]+)$").unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSkillUri {
    pub bundle: String,
    pub path: String,
}

/// Parse a `legion-skill://<bundle>/<path>` URI, rejecting path escapes.
pub fn parse_skill_uri(uri: &str) -> Result<ParsedSkillUri, String> {
    let captures = URI
        .captures(uri)
        .ok_or_else(|| format!("unsupported skill URI: {uri}"))?;
    let bundle = captures[1].to_string();
    let path = captures[2].replace('\\', "/");
    if path.split('/').any(|segment| segment == "..") || path.starts_with('/') {
        return Err("skill URI path escape".to_string());
    }
    Ok(ParsedSkillUri { bundle, path })
}

/// Build a `legion-skill://<bundle>/<path>` URI from a bundle id and relative path.
pub fn skill_uri(bundle: &str, path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.strip_prefix("./").unwrap_or(&normalized);
    format!("legion-skill://{bundle}/{trimmed}")
}
