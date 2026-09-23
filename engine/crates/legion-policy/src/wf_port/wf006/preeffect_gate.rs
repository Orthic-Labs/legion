//! PARTIAL port of `src/lib/guard/compat/effects/preeffect-gate.mjs`
//! (deliverable 6 — the pre-effect gate).
//!
//! This scoped port covers the gate's self-contained, dependency-free
//! surface only: the mutating-effect-class enum, the scope-pattern glob
//! matcher (`pathMatches`), and the workspace-relative path normalizer
//! (`workspaceRelative`). These are faithfully ported and unit tested below.
//!
//! NOT ported (budget/dependency boundary — see wf006 report): the
//! `PreEffectGate` class itself (`check()`/`checkTwoPath()` and friends),
//! because it depends on three sibling JS modules wf006 does not own or
//! have Rust equivalents for yet:
//!   - `contracts/arcane/validate.mjs` (`validateAgainst`) — schema
//!     validation against the frozen effect-request contract shape;
//!   - `contracts/arcane/authority.mjs` (`requireAuthority`) — kernel-
//!     asserted authority lookup for the current turn;
//!   - `lib/policy.mjs` — the actual allow/deny policy the gate consults;
//!     the gate itself "holds no policy of its own" (file header).
//! Porting the class faithfully needs those three ported first (or stubbed
//! behind traits) plus the full ~650-line check-order state machine
//! (capability check, path ownership, two-path FILE_MOVE handling, effect
//! class authorization, contract version, latitude class, approval ladder).
//! That is a separate, larger wf ticket; this file leaves the utilities the
//! class will need already in place and tested.

/// Every value in the frozen `EFFECT_CLASS` enum that mutates product state
/// or may do so. Read-only work never arrives as an effect request at all.
pub const MUTATING_EFFECT_CLASSES: &[&str] = &[
    "FILE_WRITE", "FILE_DELETE", "FILE_MOVE", "COMMAND_EXEC", "NETWORK_EGRESS",
    "PROCESS_SPAWN", "CREDENTIAL_ACCESS", "DEPENDENCY_INSTALL", "VCS_COMMIT",
    "VCS_PUSH", "PUBLISH", "EXTERNAL_SIDE_EFFECT",
];

pub fn is_mutating(effect_class: &str) -> bool {
    MUTATING_EFFECT_CLASSES.contains(&effect_class)
}

/// Effect classes whose request carries a second path that must also be owned.
pub const TWO_PATH_EFFECTS: &[&str] = &["FILE_MOVE"];

#[allow(dead_code)]
pub fn is_two_path_effect(effect_class: &str) -> bool {
    TWO_PATH_EFFECTS.contains(&effect_class)
}

fn normalize_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut last_was_slash = false;
    for c in p.chars() {
        let c = if c == '\\' { '/' } else { c };
        if c == '/' {
            if last_was_slash {
                continue;
            }
            last_was_slash = true;
        } else {
            last_was_slash = false;
        }
        out.push(c);
    }
    out
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Translate a `pathMatches` scope pattern into a compiled matcher, then
/// test `target` against it. Deliberately small: `**` (any number of
/// segments), `*` (within one segment), a trailing `/` (directory prefix),
/// literal paths. A target containing a `..` segment never matches.
pub fn path_matches(pattern: &str, target: &str) -> bool {
    let t = normalize_path(target);
    if t.split('/').any(|seg| seg == "..") {
        return false;
    }
    let mut p = normalize_path(pattern);
    if p.ends_with('/') {
        p.push_str("**");
    }
    let segments: Vec<&str> = p.split('/').collect();
    let mut rx = String::from("^");
    for (index, segment) in segments.iter().enumerate() {
        let separator = if index > 0 && segments[index - 1] != "**" { "/" } else { "" };
        if *segment == "**" {
            rx.push_str(separator);
            if index == segments.len() - 1 {
                rx.push_str(".*");
            } else {
                rx.push_str("(?:[^/]+/)*");
            }
        } else {
            rx.push_str(separator);
            // Split on `*`, escaping literal runs and mapping `*` -> `[^/]*`.
            let mut chars = segment.chars().peekable();
            let mut literal = String::new();
            while let Some(c) = chars.next() {
                if c == '*' {
                    rx.push_str(&regex_escape(&literal));
                    literal.clear();
                    rx.push_str("[^/]*");
                } else {
                    literal.push(c);
                }
            }
            rx.push_str(&regex_escape(&literal));
        }
    }
    rx.push('$');
    simple_glob_regex_match(&rx, &t)
}

/// Minimal backtracking matcher for the small regex subset `path_matches`
/// produces (`^`, `$`, literal chars, `[^/]*`, `(?:[^/]+/)*`, `.*`) — kept
/// dependency-free rather than pulling in the `regex` crate for wf006.
fn simple_glob_regex_match(rx: &str, text: &str) -> bool {
    // Reduce the small generated grammar back into matcher tokens instead of
    // interpreting arbitrary regex syntax.
    #[derive(Debug)]
    enum Tok {
        Lit(char),
        StarNonSlash,   // [^/]*
        StarAny,        // .*
        StarSegments,   // (?:[^/]+/)*
    }
    let mut toks = Vec::new();
    let body = &rx[1..rx.len() - 1]; // strip ^ and $
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' && chars.clone().take(3).collect::<String>() == "^/]" {
            chars.next();
            chars.next();
            chars.next();
            if chars.peek() == Some(&'*') {
                chars.next();
                toks.push(Tok::StarNonSlash);
            }
        } else if c == '.' && chars.peek() == Some(&'*') {
            chars.next();
            toks.push(Tok::StarAny);
        } else if c == '(' {
            // expect "?:[^/]+/)*"
            let rest: String = chars.by_ref().take(10).collect();
            if rest == "?:[^/]+/)*" {
                toks.push(Tok::StarSegments);
            }
        } else if c == '\\' {
            if let Some(next) = chars.next() {
                toks.push(Tok::Lit(next));
            }
        } else {
            toks.push(Tok::Lit(c));
        }
    }
    let text_chars: Vec<char> = text.chars().collect();
    fn matches_from(toks: &[Tok], ti: usize, text: &[char], si: usize) -> bool {
        if ti == toks.len() {
            return si == text.len();
        }
        match &toks[ti] {
            Tok::Lit(c) => si < text.len() && text[si] == *c && matches_from(toks, ti + 1, text, si + 1),
            Tok::StarNonSlash => {
                let mut end = si;
                loop {
                    if matches_from(toks, ti + 1, text, end) {
                        return true;
                    }
                    if end >= text.len() || text[end] == '/' {
                        return false;
                    }
                    end += 1;
                }
            }
            Tok::StarAny => {
                let mut end = si;
                loop {
                    if matches_from(toks, ti + 1, text, end) {
                        return true;
                    }
                    if end >= text.len() {
                        return false;
                    }
                    end += 1;
                }
            }
            Tok::StarSegments => {
                // Zero or more `[^/]+/` groups.
                let mut end = si;
                loop {
                    if matches_from(toks, ti + 1, text, end) {
                        return true;
                    }
                    // Try to consume one more segment.
                    let seg_start = end;
                    let mut seg_end = end;
                    while seg_end < text.len() && text[seg_end] != '/' {
                        seg_end += 1;
                    }
                    if seg_end == seg_start || seg_end >= text.len() || text[seg_end] != '/' {
                        return false;
                    }
                    end = seg_end + 1;
                }
            }
        }
    }
    matches_from(&toks, 0, &text_chars, 0)
}

pub fn matches_any(patterns: &[&str], target: &str) -> bool {
    patterns.iter().any(|p| path_matches(p, target))
}

/// Bring a host-supplied path into the same frame as `scope.own`. A path
/// outside the workspace is returned unchanged (still fails to match, still
/// denied). Drive-letter/prefix comparison is case-insensitive, matching the
/// JS source's rationale (host payload vs. contract casing can differ).
pub fn workspace_relative(target: &str, workspace: Option<&str>) -> String {
    let t = normalize_path(target);
    let workspace = match workspace {
        Some(w) if !w.is_empty() => w,
        _ => return t,
    };
    let mut root = normalize_path(workspace);
    if root.ends_with('/') {
        root.pop();
    }
    if root.is_empty() {
        return t;
    }
    let prefix = format!("{root}/");
    if t.len() >= prefix.len() && t[..prefix.len()].to_lowercase() == prefix.to_lowercase() {
        t[prefix.len()..].to_string()
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutating_effect_classes_contains_file_write_not_file_read() {
        assert!(is_mutating("FILE_WRITE"));
        assert!(!is_mutating("FILE_READ"));
    }

    #[test]
    fn path_matches_literal() {
        assert!(path_matches("src/lib/guard/mod.rs", "src/lib/guard/mod.rs"));
        assert!(!path_matches("src/lib/guard/mod.rs", "src/lib/other.rs"));
    }

    #[test]
    fn path_matches_single_star_stays_within_segment() {
        assert!(path_matches("src/*.rs", "src/lib.rs"));
        assert!(!path_matches("src/*.rs", "src/sub/lib.rs"));
    }

    #[test]
    fn path_matches_double_star_crosses_segments() {
        assert!(path_matches("src/**/mod.rs", "src/a/b/mod.rs"));
        assert!(path_matches("src/**/mod.rs", "src/mod.rs"));
    }

    #[test]
    fn path_matches_trailing_slash_is_directory_prefix() {
        assert!(path_matches("engine/crates/", "engine/crates/legion-policy/src/lib.rs"));
        assert!(!path_matches("engine/crates/", "other/legion-policy/src/lib.rs"));
    }

    #[test]
    fn path_matches_rejects_dot_dot_traversal() {
        assert!(!path_matches("**", "a/../b"));
    }

    #[test]
    fn matches_any_checks_every_pattern() {
        assert!(matches_any(&["a/*.rs", "b/*.rs"], "b/x.rs"));
        assert!(!matches_any(&["a/*.rs", "b/*.rs"], "c/x.rs"));
    }

    #[test]
    fn workspace_relative_strips_matching_prefix_case_insensitively() {
        assert_eq!(workspace_relative("/Work/Repo/src/lib.rs", Some("/work/repo")), "src/lib.rs");
    }

    #[test]
    fn workspace_relative_leaves_outside_paths_unchanged() {
        assert_eq!(workspace_relative("/elsewhere/lib.rs", Some("/work/repo")), "/elsewhere/lib.rs");
    }

    #[test]
    fn workspace_relative_without_workspace_returns_normalized_target() {
        assert_eq!(workspace_relative("a//b\\c", None), "a/b/c");
    }
}
