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
//! ## Packet r50: the remaining stateful functions
//! `commitReceiptRequirement`, `preEffectDiscipline`'s receipt-verification
//! branch, `recordCommitAdvisory`, and `auditSuccessfulCommit` are now
//! ported too, closing the file. They build on
//! `legion_policy::wf_port::wf002::minimize` (`repository_root`,
//! `staged_changes`, `read_json`, `verify_receipt` — the Rust port of
//! `src/lib/cognitive/arcane/minimize.mjs`, already reachable from
//! `legion-runtime` via the existing `legion-policy` dependency) and
//! `legion_policy::wf_port::wf007::policy::PolicyEngine` (`locked_domains_for`).
//!
//! `canonical()`/`relative()` (Node's `fs.realpathSync`/`path.relative`) have
//! no direct `std::path` equivalent for arbitrary paths, so
//! [`canonical_path`]/[`relative_path`] below reimplement them: canonicalize
//! resolves symlinks like `realpathSync` and falls back to the original path
//! on failure (mirroring the JS `try { realpathSync } catch { return target }`);
//! `relative_path` walks both paths' `Component`s to find the shared prefix
//! and joins `..`/remaining components with `/`, matching
//! `path.relative(...).replaceAll('\\', '/')` component-wise rather than by
//! string surgery (Windows' `\\?\` canonicalize prefix is stripped before
//! that walk, per the port brief's pitfall list).

use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use legion_policy::wf_port::wf002::minimize::{
    read_json, repository_root, staged_changes, verify_receipt, MinimizeEnv, ReceiptPaths,
};
use legion_policy::wf_port::wf007::policy::PolicyEngine;

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

/// The three states `!policy || policy.failClosed || typeof
/// policy.lockedDomainsFor !== 'function'` distinguishes in
/// `commitReceiptRequirement`. Rust's type system already keeps
/// `PolicyEngine` (which has `locked_domains_for`) separate from a
/// fail-closed placeholder, so this enum is the faithful equivalent of that
/// tri-state check rather than a duck-typed object.
pub enum DisciplinePolicy<'a> {
    Available(&'a PolicyEngine),
    FailClosed,
    Unavailable,
}

/// Resolves symlinks like `fs.realpathSync`, falling back to the original
/// path on failure exactly as the JS `canonical` helper does.
pub fn canonical_path(path: &Path) -> PathBuf {
    match std::fs::canonicalize(path) {
        Ok(resolved) => strip_windows_verbatim_prefix(resolved),
        Err(_) => path.to_path_buf(),
    }
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

/// `path.relative(from, to)`, forward-slash joined. Component-wise, not
/// string surgery: walks both paths' `Component`s to the first divergence,
/// then emits one `..` per remaining `from` component followed by the
/// remaining `to` components.
pub fn relative_path(from: &Path, to: &Path) -> String {
    let from_components: Vec<Component<'_>> = from.components().collect();
    let to_components: Vec<Component<'_>> = to.components().collect();
    let mut common = 0usize;
    while common < from_components.len() && common < to_components.len() && from_components[common] == to_components[common] {
        common += 1;
    }
    let mut parts: Vec<String> = Vec::new();
    for _ in common..from_components.len() {
        parts.push("..".to_string());
    }
    for component in &to_components[common..] {
        parts.push(component.as_os_str().to_string_lossy().to_string());
    }
    parts.join("/")
}

/// `path.resolve(base, rel)`: absolute `rel` wins outright, otherwise `rel`
/// is joined onto `base` and `.`/`..` components are collapsed without
/// touching the filesystem (no symlink resolution — that is `canonical_path`'s
/// job, done separately, matching the JS split between `resolve` and
/// `realpathSync`).
pub fn resolve_path(base: &str, rel: &str) -> String {
    let rel_path = Path::new(rel);
    let joined = if rel_path.is_absolute() { rel_path.to_path_buf() } else { Path::new(base).join(rel_path) };
    let mut out: Vec<Component<'_>> = Vec::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push(component);
                }
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out.into_iter().collect::<PathBuf>().to_string_lossy().to_string()
}

#[derive(Debug, Clone, Default)]
pub struct CommitReceiptRequirement {
    pub required: bool,
    pub reason: &'static str,
    pub paths: Vec<String>,
    pub locked: Vec<(String, String, String, Option<String>)>,
    pub advisory: Option<String>,
}

/// Port of `commitReceiptRequirement`.
pub fn commit_receipt_requirement(
    workspace: &Path,
    repository: &Path,
    policy: &DisciplinePolicy<'_>,
    contracted: bool,
) -> CommitReceiptRequirement {
    if contracted {
        return CommitReceiptRequirement { required: true, reason: "contracted-work", ..Default::default() };
    }
    let engine = match policy {
        DisciplinePolicy::Available(engine) => *engine,
        DisciplinePolicy::FailClosed | DisciplinePolicy::Unavailable => {
            return CommitReceiptRequirement {
                required: false,
                reason: "policy-unavailable",
                advisory: Some("commit tier could not be classified; ambient commit allowed with advisory".to_string()),
                ..Default::default()
            };
        }
    };

    let paths = match gather_repository_paths(workspace, repository) {
        Ok(paths) => paths,
        Err(message) => {
            return CommitReceiptRequirement {
                required: false,
                reason: "staged-paths-unavailable",
                advisory: Some(format!("staged paths could not be classified: {message}")),
                ..Default::default()
            };
        }
    };

    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let locked = engine.locked_domains_for(&path_refs);
    if !locked.is_empty() {
        CommitReceiptRequirement { required: true, reason: "locked-domain", paths, locked, advisory: None }
    } else {
        CommitReceiptRequirement { required: false, reason: "ambient", paths, ..Default::default() }
    }
}

fn gather_repository_paths(workspace: &Path, repository: &Path) -> Result<Vec<String>, String> {
    let requested_repository = canonical_path(repository);
    let reported_root_raw = repository_root(repository).map_err(|e| e.to_string())?;
    let reported_root = canonical_path(Path::new(&reported_root_raw));
    // Git process state can leak a foreign worktree into rev-parse on hosted
    // Windows runners: never frame paths from a root that does not contain
    // the repository the caller asked us to inspect.
    let root = if contains_path(&relative_path(&reported_root, &requested_repository)) {
        reported_root
    } else {
        requested_repository
    };

    let env = MinimizeEnv::default();
    let repository_paths: Vec<String> = staged_changes(repository, &env)
        .map_err(|e| e.to_string())?
        .into_iter()
        .flat_map(|change| match change.source {
            Some(source) => vec![source, change.path],
            None => vec![change.path],
        })
        .collect();

    let base = canonical_path(workspace);
    let repository_prefix = relative_path(&base, &root).replace('\\', "/");

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for path in repository_paths {
        let normalized = path.replace('\\', "/");
        let joined = [repository_prefix.as_str(), normalized.as_str()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        if seen.insert(joined.clone()) {
            out.push(joined);
        }
    }
    Ok(out)
}

/// Manual civil-calendar computation (Howard Hinnant's `civil_from_days`),
/// matching the pattern used elsewhere in this workspace (e.g.
/// `legion-audit`'s `iso8601_now`) so no date/time crate dependency is
/// needed for the audit-trail timestamps below.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn iso8601_now() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{:03}Z", now.subsec_millis())
}

fn append_jsonl(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", serde_json::to_string(value).unwrap_or_default())
}

/// Port of `recordCommitAdvisory`: an advisory must never become a commit
/// blocker, so any I/O failure here is swallowed exactly as the JS
/// `try {} catch {}` does.
pub fn record_commit_advisory(workspace: &Path, message: &str) {
    let audit_dir = workspace.join(".audit").join("arcane");
    let _ = append_jsonl(
        &audit_dir.join("commit-discipline-advisories.jsonl"),
        &json!({ "kind": "arcane-commit-discipline-advisory", "message": message, "observedAt": iso8601_now() }),
    );
}

/// Minimal host-event shape `auditSuccessfulCommit` reads.
#[derive(Debug, Clone, Default)]
pub struct DisciplineHostEvent {
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub source_revision: Option<String>,
}

/// Port of `auditSuccessfulCommit`.
pub fn audit_successful_commit(payload: &DisciplinePayload, host_event: &DisciplineHostEvent, workspace: &Path) {
    let command = extract_discipline_shell_command(payload);
    if !is_commit_command(&command) || host_event.event_type.as_deref() != Some("post-effect") || host_event.outcome.as_deref() != Some("success") {
        return;
    }
    let mut truncated = command;
    truncated.truncate(500);
    let record = json!({
        "event": "git-commit",
        "sessionId": host_event.session_id,
        "runId": host_event.run_id,
        "sourceRevision": host_event.source_revision,
        "command": truncated,
    });
    let audit_dir = workspace.join(".audit").join("arcane");
    let _ = append_jsonl(&audit_dir.join("commit-identity.jsonl"), &record);
}

/// Port of `preEffectDiscipline`, composing [`pre_effect_discipline_prefix`]
/// with the commit-receipt branch. `resolve_fn` is threaded through to
/// [`commit_repository`] exactly as that function already requires;
/// [`resolve_path`] is the faithful default for real `path.resolve`
/// semantics.
///
/// Note on `verify_receipt`'s `cwd`: the JS `verifyReceipt` call carries no
/// explicit working directory and implicitly runs relative to the host
/// process's cwd. This port makes that binding explicit by passing the
/// resolved commit `repository` path, which is the directory the commit
/// itself targets and therefore the only correct anchor for staged-tree
/// verification in a port that must work from any process cwd.
pub fn pre_effect_discipline(
    payload: &DisciplinePayload,
    workspace: &Path,
    policy: &DisciplinePolicy<'_>,
    contracted: bool,
    check_commit: bool,
) -> Option<DisciplineDenial> {
    if let Some(denial) = pre_effect_discipline_prefix(payload) {
        return Some(denial);
    }
    let command = extract_discipline_shell_command(payload);
    if !is_commit_command(&command) || !check_commit {
        return None;
    }

    let repository_string = commit_repository(payload, &workspace.to_string_lossy(), resolve_path);
    let repository = Path::new(&repository_string);
    let requirement = commit_receipt_requirement(workspace, repository, policy, contracted);
    if !requirement.required {
        if let Some(advisory) = &requirement.advisory {
            record_commit_advisory(workspace, advisory);
        }
        return None;
    }

    let receipt_path = workspace.join(".audit").join("minimize").join("commit-receipt.json");
    let policy_path = workspace.join("tools").join("skills").join("legion").join("packages").join("arcane").join("policy").join("minimize-policy.md");
    let validator_path = workspace.join("tools").join("skills").join("legion").join("packages").join("arcane").join("lib").join("minimize.mjs");

    if !receipt_path.exists() {
        return Some(DisciplineDenial { code: "ARC_CLAIM_PREREQUISITE_UNMET", message: "commit receipt is missing".to_string() });
    }
    let receipt = match read_json(&receipt_path) {
        Ok(value) => value,
        Err(error) => return Some(DisciplineDenial { code: "ARC_CLAIM_PREREQUISITE_UNMET", message: error.to_string() }),
    };
    let receipt_paths = ReceiptPaths { policy_path: &policy_path, validator_path: &validator_path };
    let env = MinimizeEnv::default();
    match verify_receipt(&receipt, &receipt_paths, repository, &env) {
        Ok(_) => None,
        Err(error) => Some(DisciplineDenial { code: "ARC_CLAIM_PREREQUISITE_UNMET", message: error.to_string() }),
    }
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

    #[test]
    fn relative_path_computes_ups_and_downs() {
        assert_eq!(relative_path(Path::new("/a/b/c"), Path::new("/a/b/d/e")), "../d/e");
        assert_eq!(relative_path(Path::new("/a/b"), Path::new("/a/b")), "");
        assert_eq!(relative_path(Path::new("/a"), Path::new("/a/b")), "b");
    }

    #[test]
    fn resolve_path_collapses_dot_segments() {
        assert_eq!(resolve_path("/workspace", "sub"), "/workspace/sub");
        assert_eq!(resolve_path("/workspace/sub", "../other"), "/workspace/other");
        assert_eq!(resolve_path("/workspace", "/abs/path"), "/abs/path");
    }

    #[test]
    fn canonical_path_falls_back_when_missing() {
        let missing = Path::new("/definitely/does/not/exist/legion-r50");
        assert_eq!(canonical_path(missing), missing.to_path_buf());
    }

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("legion-discipline-{}-{}-{n}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git_ok(cwd: &Path, args: &[&str]) {
        let status = std::process::Command::new("git").current_dir(cwd).args(args).status().expect("git available");
        assert!(status.success(), "git {args:?} failed");
    }

    fn git_repo() -> PathBuf {
        let root = temp_dir("repo");
        git_ok(&root, &["init", "-q"]);
        git_ok(&root, &["config", "user.email", "t@t"]);
        git_ok(&root, &["config", "user.name", "t"]);
        std::fs::write(root.join("a.txt"), "one\n").unwrap();
        git_ok(&root, &["add", "-A"]);
        git_ok(&root, &["commit", "-qm", "base"]);
        root
    }

    #[test]
    fn commit_receipt_requirement_contracted_is_always_required() {
        let workspace = temp_dir("contracted");
        let req = commit_receipt_requirement(&workspace, &workspace, &DisciplinePolicy::Unavailable, true);
        assert!(req.required);
        assert_eq!(req.reason, "contracted-work");
    }

    #[test]
    fn commit_receipt_requirement_unavailable_policy_is_advisory() {
        let workspace = temp_dir("unavailable-policy");
        let req = commit_receipt_requirement(&workspace, &workspace, &DisciplinePolicy::Unavailable, false);
        assert!(!req.required);
        assert_eq!(req.reason, "policy-unavailable");
        assert!(req.advisory.is_some());
    }

    #[test]
    fn commit_receipt_requirement_fail_closed_policy_is_advisory() {
        let workspace = temp_dir("fail-closed-policy");
        let req = commit_receipt_requirement(&workspace, &workspace, &DisciplinePolicy::FailClosed, false);
        assert!(!req.required);
        assert_eq!(req.reason, "policy-unavailable");
    }

    fn empty_policy_engine() -> PolicyEngine {
        PolicyEngine::new(legion_policy::wf_port::wf007::policy::PolicyBundle {
            policy_id: "test".to_string(),
            version: 1,
            digest: "sha256:test".to_string(),
            effect_rules: vec![],
            waiver_authority: vec![],
            claim_levels: Default::default(),
            locked_domains: vec![],
            degradation: Default::default(),
            capability: Default::default(),
            replay: Default::default(),
            trust_minima: Default::default(),
            host_enforcement: Default::default(),
            evidence: Default::default(),
            retention: Default::default(),
        })
    }

    #[test]
    fn commit_receipt_requirement_ambient_when_no_locked_domains() {
        let workspace = git_repo();
        std::fs::write(workspace.join("b.txt"), "two\n").unwrap();
        git_ok(&workspace, &["add", "-A"]);
        let engine = empty_policy_engine();
        let policy = DisciplinePolicy::Available(&engine);
        let req = commit_receipt_requirement(&workspace, &workspace, &policy, false);
        assert!(!req.required);
        assert_eq!(req.reason, "ambient");
        assert!(req.paths.contains(&"b.txt".to_string()));
    }

    #[test]
    fn commit_receipt_requirement_required_when_locked_domain_matches() {
        let workspace = git_repo();
        std::fs::write(workspace.join("b.txt"), "two\n").unwrap();
        git_ok(&workspace, &["add", "-A"]);
        let engine = PolicyEngine::new(legion_policy::wf_port::wf007::policy::PolicyBundle {
            policy_id: "test".to_string(),
            version: 1,
            digest: "sha256:test".to_string(),
            effect_rules: vec![],
            waiver_authority: vec![],
            claim_levels: Default::default(),
            locked_domains: vec![legion_policy::wf_port::wf007::policy::LockedDomainEntry {
                pattern: "b.txt".to_string(),
                claim_level: "strict".to_string(),
                note: None,
            }],
            degradation: Default::default(),
            capability: Default::default(),
            replay: Default::default(),
            trust_minima: Default::default(),
            host_enforcement: Default::default(),
            evidence: Default::default(),
            retention: Default::default(),
        });
        let policy = DisciplinePolicy::Available(&engine);
        let req = commit_receipt_requirement(&workspace, &workspace, &policy, false);
        assert!(req.required);
        assert_eq!(req.reason, "locked-domain");
        assert_eq!(req.locked.len(), 1);
    }

    #[test]
    fn record_commit_advisory_appends_jsonl() {
        let workspace = temp_dir("advisory");
        record_commit_advisory(&workspace, "ambient commit allowed");
        let path = workspace.join(".audit").join("arcane").join("commit-discipline-advisories.jsonl");
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("ambient commit allowed"));
        assert!(text.contains("arcane-commit-discipline-advisory"));
    }

    #[test]
    fn audit_successful_commit_writes_only_on_post_effect_success() {
        let workspace = temp_dir("audit-commit");
        let payload = DisciplinePayload { command: Some("git commit -m x".to_string()), ..Default::default() };
        let non_matching = DisciplineHostEvent { event_type: Some("pre-effect".to_string()), outcome: Some("success".to_string()), ..Default::default() };
        audit_successful_commit(&payload, &non_matching, &workspace);
        let path = workspace.join(".audit").join("arcane").join("commit-identity.jsonl");
        assert!(!path.exists());

        let matching = DisciplineHostEvent {
            event_type: Some("post-effect".to_string()),
            outcome: Some("success".to_string()),
            session_id: Some("s1".to_string()),
            run_id: Some("r1".to_string()),
            source_revision: Some("abc123".to_string()),
        };
        audit_successful_commit(&payload, &matching, &workspace);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("git-commit"));
        assert!(text.contains("s1"));
    }

    #[test]
    fn pre_effect_discipline_short_circuits_on_no_verify_before_touching_policy() {
        let workspace = temp_dir("pre-effect-no-verify");
        let payload = DisciplinePayload { command: Some("git commit --no-verify".to_string()), ..Default::default() };
        let denial = pre_effect_discipline(&payload, &workspace, &DisciplinePolicy::Unavailable, false, true).unwrap();
        assert_eq!(denial.code, "ARC_EFFECT_CLASS_UNAUTHORIZED");
    }

    #[test]
    fn pre_effect_discipline_skips_commit_check_when_disabled() {
        let workspace = temp_dir("pre-effect-skip");
        let payload = DisciplinePayload { command: Some("git commit -m x".to_string()), ..Default::default() };
        assert!(pre_effect_discipline(&payload, &workspace, &DisciplinePolicy::Unavailable, false, false).is_none());
    }

    #[test]
    fn pre_effect_discipline_records_advisory_when_ambient() {
        let workspace = git_repo();
        std::fs::write(workspace.join("b.txt"), "two\n").unwrap();
        git_ok(&workspace, &["add", "-A"]);
        let engine = empty_policy_engine();
        let policy = DisciplinePolicy::Available(&engine);
        let payload = DisciplinePayload { command: Some("git commit -m x".to_string()), ..Default::default() };
        let result = pre_effect_discipline(&payload, &workspace, &policy, false, true);
        assert!(result.is_none());
        let advisory_path = workspace.join(".audit").join("arcane").join("commit-discipline-advisories.jsonl");
        assert!(!advisory_path.exists(), "ambient reason carries no advisory to record");
    }

    #[test]
    fn pre_effect_discipline_blocks_locked_domain_without_receipt() {
        let workspace = git_repo();
        std::fs::write(workspace.join("b.txt"), "two\n").unwrap();
        git_ok(&workspace, &["add", "-A"]);
        let engine = PolicyEngine::new(legion_policy::wf_port::wf007::policy::PolicyBundle {
            policy_id: "test".to_string(),
            version: 1,
            digest: "sha256:test".to_string(),
            effect_rules: vec![],
            waiver_authority: vec![],
            claim_levels: Default::default(),
            locked_domains: vec![legion_policy::wf_port::wf007::policy::LockedDomainEntry {
                pattern: "b.txt".to_string(),
                claim_level: "strict".to_string(),
                note: None,
            }],
            degradation: Default::default(),
            capability: Default::default(),
            replay: Default::default(),
            trust_minima: Default::default(),
            host_enforcement: Default::default(),
            evidence: Default::default(),
            retention: Default::default(),
        });
        let policy = DisciplinePolicy::Available(&engine);
        let payload = DisciplinePayload { command: Some("git commit -m x".to_string()), ..Default::default() };
        let denial = pre_effect_discipline(&payload, &workspace, &policy, false, true).unwrap();
        assert_eq!(denial.code, "ARC_CLAIM_PREREQUISITE_UNMET");
        assert!(denial.message.contains("missing"));
    }
}
