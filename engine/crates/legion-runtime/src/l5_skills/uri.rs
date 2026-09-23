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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bundle_and_path() {
        let parsed = parse_skill_uri("legion-skill://qa/SKILL.md").unwrap();
        assert_eq!(parsed.bundle, "qa");
        assert_eq!(parsed.path, "SKILL.md");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(parse_skill_uri("https://example.com/x").is_err());
    }

    #[test]
    fn rejects_parent_escape() {
        assert!(parse_skill_uri("legion-skill://qa/../secret.md").is_err());
    }

    #[test]
    fn rejects_absolute_path() {
        assert!(parse_skill_uri("legion-skill://qa//etc/passwd").is_err());
    }

    #[test]
    fn builds_uri_and_strips_dot_slash_prefix() {
        assert_eq!(skill_uri("qa", "./references/a.md"), "legion-skill://qa/references/a.md");
        assert_eq!(skill_uri("qa", "a\\b.md"), "legion-skill://qa/a/b.md");
    }
}
