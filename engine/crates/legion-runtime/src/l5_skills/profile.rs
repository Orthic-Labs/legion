//! Profile projection for packaged skills.
//!
//! Ported from `src/lib/skills/profile.mjs`. Loading a skill under the audit
//! profile strips instructions that would let a read-only reader mutate
//! anything, and rewrites relative links to package URIs so a projected
//! document never points outside the package.

use super::uri::skill_uri;
use regex::{Captures, Regex};
use std::sync::LazyLock;

static DOCUMENT_EXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:^|\.)(?:md|mdx|txt)$").unwrap());
static LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\]\((?P<target>[^)\s]+)\)").unwrap());
static ALLOWED_TOOLS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^allowed-tools:.*\n?").unwrap());
static TOOLS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^tools:.*\n?").unwrap());
static PERMISSION_MODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^permission-mode:.*\n?").unwrap());
static AUTOMATIC_EFFECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^.*\b(?:publish|deploy|commit|push)\b.*automatically.*\n?").unwrap()
});
static MUTATION_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\s*(?:[-*]|\d+[.)])?\s*(?:write|edit|bash|fix|apply|modify|implement|deploy|publish|commit|push)\b.*\n?").unwrap()
});
static AUDIT_FIX_REFERENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^.*/(?:audit-fix|fix)\b.*\n?").unwrap());

fn is_document(path: &str) -> bool {
    DOCUMENT_EXT.is_match(path)
}

/// Join a POSIX-style relative reference against a document's own directory and normalize `.`/`..`.
fn join_relative(dir: &str, target: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    let mut leading_escapes = 0usize;
    for part in dir.split('/').chain(target.split('/')) {
        match part {
            "" | "." => continue,
            ".." => {
                if segments.pop().is_none() {
                    leading_escapes += 1;
                }
            }
            other => segments.push(other),
        }
    }
    let mut parts: Vec<&str> = Vec::with_capacity(leading_escapes + segments.len());
    for _ in 0..leading_escapes {
        parts.push("..");
    }
    parts.extend(segments);
    parts.join("/")
}

fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[..index],
        None => "",
    }
}

fn rewrite_links(value: &str, bundle: &str, path: &str) -> String {
    let normalized_path = path.replace('\\', "/");
    let dir = dirname(&normalized_path);
    LINK
        .replace_all(value, |captures: &Captures| {
            let target = &captures["target"];
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || target.starts_with('#')
                || target.starts_with("legion-skill:")
            {
                return captures[0].to_string();
            }
            let resolved = join_relative(dir, &target.replace('\\', "/"));
            if resolved.starts_with("../") || resolved == ".." {
                "](<external-reference>)".to_string()
            } else {
                format!("]({})", skill_uri(bundle, &resolved))
            }
        })
        .into_owned()
}

fn strip_audit_instructions(value: &str) -> String {
    let mut out = value.to_string();
    for pattern in [&*ALLOWED_TOOLS, &*TOOLS, &*PERMISSION_MODE, &*AUTOMATIC_EFFECT, &*MUTATION_LINE, &*AUDIT_FIX_REFERENCE] {
        out = pattern.replace_all(&out, "").into_owned();
    }
    out
}

/// Project packaged skill text for a given read profile (`"audit"` or `"authoring"`).
pub fn project_skill_text(text: &str, bundle: &str, path: &str, profile: &str) -> String {
    let mut value = text.replace("\r\n", "\n").replace('\r', "\n");
    if is_document(path) {
        value = rewrite_links(&value, bundle, path);
    }
    if profile == "audit" && is_document(path) {
        value = strip_audit_instructions(&value);
    }
    if value.ends_with('\n') {
        value
    } else {
        format!("{value}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_relative_links_to_package_uris() {
        let text = "See [ref](references/notes.md) for more.\n";
        let projected = project_skill_text(text, "qa", "SKILL.md", "authoring");
        assert!(projected.contains("legion-skill://qa/references/notes.md"));
    }

    #[test]
    fn marks_parent_escapes_as_external() {
        let text = "See [ref](../outside.md).\n";
        let projected = project_skill_text(text, "qa", "SKILL.md", "authoring");
        assert!(projected.contains("<external-reference>"));
    }

    #[test]
    fn escape_that_normalizes_back_inside_is_rewritten_not_marked_external() {
        let text = "See [ref](../outside.md).\n";
        let projected = project_skill_text(text, "qa", "sub/SKILL.md", "authoring");
        assert!(projected.contains("legion-skill://qa/outside.md"));
    }

    #[test]
    fn leaves_absolute_and_scheme_links_untouched() {
        let text = "See [a](https://example.com) and [b](legion-skill://qa/x.md) and [c](#anchor).\n";
        let projected = project_skill_text(text, "qa", "SKILL.md", "authoring");
        assert!(projected.contains("https://example.com"));
        assert!(projected.contains("legion-skill://qa/x.md"));
        assert!(projected.contains("#anchor"));
    }

    #[test]
    fn audit_profile_strips_mutation_instructions() {
        let text = "---\nallowed-tools: Write\n---\n- Write the file\nRead only otherwise.\n";
        let projected = project_skill_text(text, "qa", "SKILL.md", "audit");
        assert!(!projected.contains("allowed-tools"));
        assert!(!projected.contains("Write the file"));
    }

    #[test]
    fn authoring_profile_keeps_mutation_instructions() {
        let text = "- Write the file\n";
        let projected = project_skill_text(text, "qa", "SKILL.md", "authoring");
        assert!(projected.contains("Write the file"));
    }

    #[test]
    fn non_document_paths_are_untouched() {
        let text = "write to disk\n";
        let projected = project_skill_text(text, "qa", "script.sh", "audit");
        assert_eq!(projected, text);
    }

    #[test]
    fn ensures_trailing_newline() {
        let projected = project_skill_text("no newline", "qa", "notes.txt", "authoring");
        assert!(projected.ends_with('\n'));
    }
}
