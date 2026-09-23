//! Partial port of `src/lib/host/arcane/discipline-controls.mjs`.
//!
//! ## What is ported here (full fidelity)
//! - `unquote`, `commitRepository`, `extractDisciplineShellCommand`,
//!   `generatedLockTargets`, `containsPath` — pure string/path helpers.
//! - The `NO_VERIFY` / `COMMIT` / `GENERATED_LOCK` regex checks from
//!   `preEffectDiscipline`, exposed as [`no_verify_blocked`] and
//!   [`generated_lock_targets`] (already ported) plus [`is_commit_command`],
//!   which callers compose into the same short-circuit order the JS
//!   function uses (`--no-verify` check, then locked-target check, then
//!   "not a commit command" bail).
//!
//! ## What is NOT ported (left `NOT-STARTED`, out of this chunk)
//! - `commitReceiptRequirement`: depends on `stagedChanges`/`repositoryRoot`
//!   (git subprocess invocation) and a `policy.lockedDomainsFor` callback
//!   from `src/lib/cognitive/arcane/minimize.mjs`, none of which are part
//!   of this chunk's five files.
//! - `preEffectDiscipline`'s receipt-verification branch
//!   (`readJson`/`verifyReceipt` against `commit-receipt.json`) and
//!   `recordCommitAdvisory`/`auditSuccessfulCommit` (both `node:fs`
//!   `appendFileSync` audit-trail writers) — filesystem I/O the chunk does
//!   not own a persistence layer for.
//! A faithful port needs `minimize.mjs`'s `stagedChanges`/`repositoryRoot`/
//! `readJson`/`verifyReceipt` ported first (see chunk report).

use std::sync::LazyLock;

use regex::Regex;

static COMMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bgit(?:\s+-C\s+(?:"[^"]+"|'[^']+'|[^\s;&|]+))?\s+commit\b"#).unwrap()
});
static NO_VERIFY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bgit(?:\s+-C\s+(?:"[^"]+"|'[^']+'|[^\s;&|]+))?\s+commit\b[^\n;&|]*\s--no-verify\b"#)
        .unwrap()
});
static GENERATED_LOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[\\/])generated-lock\.json$").unwrap());
static GIT_C: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bgit\s+-C\s+("[^"]+"|'[^']+'|[^\s;&|]+)"#).unwrap());
static PATCH_TARGET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\*\*\* (?:Update|Add|Delete) File: (.+)$").unwrap());

/// Port of `unquote`: strip one layer of matching `"..."` or `'...'`.
pub fn unquote(value: &str) -> String {
    let text = value.trim();
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'') && first == last {
            return text[1..text.len() - 1].to_string();
        }
    }
    text.to_string()
}

/// Minimal payload shape the ported helpers read from: the JS functions all
/// accept either a bare `tool_input`-shaped object or one nested under
/// `payload.tool_input`. Callers assemble this from whichever hook payload
/// shape they have.
#[derive(Debug, Clone, Default)]
pub struct DisciplinePayload {
    pub command: Option<String>,
    pub tool_input_command: Option<String>,
    pub workdir: Option<String>,
    pub cwd: Option<String>,
    pub payload_cwd: Option<String>,
    pub file_path: Option<String>,
    pub path: Option<String>,
    pub patch: Option<String>,
    pub input: Option<String>,
}

/// Port of `extractDisciplineShellCommand`.
pub fn extract_discipline_shell_command(payload: &DisciplinePayload) -> String {
    payload
        .command
        .clone()
        .or_else(|| payload.tool_input_command.clone())
        .unwrap_or_default()
}

/// Port of `commitRepository`. `resolve_fn` performs `path.resolve`
/// semantics (base + relative-or-absolute path -> absolute path); callers
/// supply it since Rust's `std::path` has no built-in POSIX/Windows-aware
/// `resolve` and the JS behaviour is platform-sensitive.
pub fn commit_repository(
    payload: &DisciplinePayload,
    workspace: &str,
    resolve_fn: impl Fn(&str, &str) -> String,
) -> String {
    let command = extract_discipline_shell_command(payload);
    let workdir = payload
        .workdir
        .clone()
        .or_else(|| payload.cwd.clone())
        .or_else(|| payload.payload_cwd.clone())
        .unwrap_or_else(|| ".".to_string());
    let base = resolve_fn(workspace, &workdir);
    if let Some(cap) = GIT_C.captures(&command) {
        let raw = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        resolve_fn(&base, &unquote(raw))
    } else {
        base
    }
}

/// Port of `generatedLockTargets`.
pub fn generated_lock_targets(payload: &DisciplinePayload) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    if let Some(fp) = &payload.file_path {
        targets.push(fp.clone());
    }
    if let Some(p) = &payload.path {
        targets.push(p.clone());
    }
    let patch = payload
        .patch
        .clone()
        .or_else(|| payload.input.clone())
        .unwrap_or_default();
    for line in patch.lines() {
        if let Some(cap) = PATCH_TARGET.captures(line) {
            targets.push(cap[1].trim().to_string());
        }
    }
    targets.retain(|t| GENERATED_LOCK.is_match(t));
    targets
}

/// Port of the `containsPath` helper: true when `relative(root, target)`
/// would not need to climb out of `root` (i.e. `target` is `root` or a
/// descendant of it). Callers supply the already-computed relative path
/// (via their platform's `path.relative` equivalent) since Rust's std
/// library has no direct equivalent for arbitrary (possibly non-existent)
/// paths.
pub fn contains_path(relative_from_root_to_target: &str) -> bool {
    let framed = relative_from_root_to_target;
    framed.is_empty() || (!framed.starts_with("..") && !is_absolute_like(framed))
}

fn is_absolute_like(path: &str) -> bool {
    path.starts_with('/')
        || (path.len() >= 2 && path.as_bytes()[1] == b':')
        || path.starts_with('\\')
}

/// Port of the `NO_VERIFY.test(command)` check in `preEffectDiscipline`.
pub fn no_verify_blocked(command: &str) -> bool {
    NO_VERIFY.is_match(command)
}

/// Port of the `COMMIT.test(command)` check in `preEffectDiscipline` /
/// `auditSuccessfulCommit`.
pub fn is_commit_command(command: &str) -> bool {
    COMMIT.is_match(command)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisciplineDenial {
    pub code: &'static str,
    pub message: String,
}

/// Port of the deterministic, no-I/O prefix of `preEffectDiscipline`: the
/// `--no-verify` block and the generated-lock write-protection block. The
/// remaining branch (`commitReceiptRequirement` + receipt verification) is
/// NOT-STARTED (see module docs); callers needing full fidelity must add it
/// once `minimize.mjs` is ported and pass its result in separately.
pub fn pre_effect_discipline_prefix(payload: &DisciplinePayload) -> Option<DisciplineDenial> {
    let command = extract_discipline_shell_command(payload);
    if no_verify_blocked(&command) {
        return Some(DisciplineDenial {
            code: "ARC_EFFECT_CLASS_UNAUTHORIZED",
            message: "git commit --no-verify is blocked".to_string(),
        });
    }
    let locks = generated_lock_targets(payload);
    if let Some(first) = locks.first() {
        return Some(DisciplineDenial {
            code: "ARC_EFFECT_CLASS_UNAUTHORIZED",
            message: format!("generated-lock is write-protected: {first}"),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquote_strips_matching_quotes() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("'abc'"), "abc");
        assert_eq!(unquote("abc"), "abc");
        assert_eq!(unquote("\"abc'"), "\"abc'"); // mismatched quotes untouched
    }

    #[test]
    fn extract_discipline_shell_command_prefers_top_level() {
        let payload = DisciplinePayload {
            command: Some("top".to_string()),
            tool_input_command: Some("nested".to_string()),
            ..Default::default()
        };
        assert_eq!(extract_discipline_shell_command(&payload), "top");
    }

    #[test]
    fn extract_discipline_shell_command_falls_back_to_nested() {
        let payload = DisciplinePayload {
            tool_input_command: Some("nested".to_string()),
            ..Default::default()
        };
        assert_eq!(extract_discipline_shell_command(&payload), "nested");
    }

    fn fake_resolve(base: &str, rel: &str) -> String {
        if rel.starts_with('/') {
            rel.to_string()
        } else {
            format!("{base}/{rel}")
        }
    }

    #[test]
    fn commit_repository_uses_git_dash_c_target() {
        let payload = DisciplinePayload {
            command: Some("git -C /repo/sub commit -m x".to_string()),
            ..Default::default()
        };
        let repo = commit_repository(&payload, "/workspace", fake_resolve);
        assert_eq!(repo, "/repo/sub");
    }

    #[test]
    fn commit_repository_defaults_to_workdir() {
        let payload = DisciplinePayload {
            command: Some("git commit -m x".to_string()),
            workdir: Some("sub".to_string()),
            ..Default::default()
        };
        let repo = commit_repository(&payload, "/workspace", fake_resolve);
        assert_eq!(repo, "/workspace/sub");
    }

    #[test]
    fn generated_lock_targets_from_file_path_and_patch() {
        let payload = DisciplinePayload {
            file_path: Some("src/generated-lock.json".to_string()),
            patch: Some("*** Update File: pkg/generated-lock.json\nsome diff".to_string()),
            ..Default::default()
        };
        let targets = generated_lock_targets(&payload);
        assert_eq!(targets, vec!["src/generated-lock.json", "pkg/generated-lock.json"]);
    }

    #[test]
    fn generated_lock_targets_ignores_unrelated_files() {
        let payload = DisciplinePayload { file_path: Some("src/main.rs".to_string()), ..Default::default() };
        assert!(generated_lock_targets(&payload).is_empty());
    }

    #[test]
    fn contains_path_accepts_descendant_and_self() {
        assert!(contains_path(""));
        assert!(contains_path("sub/dir"));
        assert!(!contains_path("../escaped"));
        assert!(!contains_path("/abs/path"));
    }

    #[test]
    fn no_verify_blocked_detects_flag() {
        assert!(no_verify_blocked("git commit -m x --no-verify"));
        assert!(!no_verify_blocked("git commit -m x"));
    }

    #[test]
    fn is_commit_command_matches_git_commit() {
        assert!(is_commit_command("git commit -m x"));
        assert!(is_commit_command("git -C /repo commit -m x"));
        assert!(!is_commit_command("git status"));
    }

    #[test]
    fn pre_effect_discipline_prefix_blocks_no_verify() {
        let payload = DisciplinePayload { command: Some("git commit --no-verify".to_string()), ..Default::default() };
        let denial = pre_effect_discipline_prefix(&payload).unwrap();
        assert_eq!(denial.code, "ARC_EFFECT_CLASS_UNAUTHORIZED");
        assert!(denial.message.contains("no-verify"));
    }

    #[test]
    fn pre_effect_discipline_prefix_blocks_generated_lock_write() {
        let payload = DisciplinePayload {
            command: Some("apply_patch".to_string()),
            file_path: Some("packages/generated-lock.json".to_string()),
            ..Default::default()
        };
        let denial = pre_effect_discipline_prefix(&payload).unwrap();
        assert!(denial.message.contains("generated-lock.json"));
    }

    #[test]
    fn pre_effect_discipline_prefix_allows_clean_commit() {
        let payload = DisciplinePayload { command: Some("git commit -m x".to_string()), ..Default::default() };
        assert!(pre_effect_discipline_prefix(&payload).is_none());
    }
}
