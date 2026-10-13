//! L1 literal port of `src/lib/handoff/validate_handoff.py`.
//!
//! Fail-closed validator for zero-memory cold-start handoffs: heading order,
//! label presence/concreteness, resume-step structure, decision/artifact
//! table shape, readiness/proceed/work-type enums, gap-severity coherence,
//! author-gate checklist, banned phrases, and secret-pattern scanning.
//!
//! The Python CLI (`argparse` + receipt read/write to disk) is not ported:
//! this module exposes the pure validation core (`validate`, `storage_errors`,
//! path normalization) as a library so a caller wires its own I/O.

use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const FORBIDDEN_STORAGE_PARTS: &[&str] = &[
    "temp",
    "tmp",
    ".tmp",
    "temporary",
    "cache",
    ".cache",
    "review-run",
    "review-runs",
    ".review-runs",
    ".council-runs",
    "scratch",
];

pub fn clean_path_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

/// Lexical, metadata-only path normalization: unifies separators and trims a
/// trailing `/`; for non-drive-letter paths it also collapses `.`/`..`
/// segments, while drive-letter paths (`C:/...`) are NOT dot-collapsed.
/// Optional Windows case-folding. It never touches the filesystem and is NOT
/// a filesystem identity guarantee: symlinks, junctions, and `..` through a
/// link are not followed. Do not use it alone for an authority decision;
/// storage authorization goes through [`resolve_physical_existing`] /
/// [`resolve_physical_receipt`] (see [`storage_errors`]). It remains valid for
/// comparing declared packet text and for command-string binding.
pub fn normalized_path(value: &str, windows: bool) -> String {
    let raw = clean_path_value(value).replace('\\', "/");
    let drive_re = drive_re();
    let normalized = if drive_re.is_match(&raw) {
        raw.trim_end_matches('/').to_string()
    } else {
        lexical_resolve(&raw)
    };
    if windows {
        normalized.to_lowercase()
    } else {
        normalized
    }
}

fn lexical_resolve(raw: &str) -> String {
    let is_abs = raw.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    let prefixed = if is_abs { format!("/{joined}") } else { joined };
    prefixed.trim_end_matches('/').to_string()
}

pub fn is_absolute_path(value: &str) -> bool {
    let raw = clean_path_value(value).replace('\\', "/");
    drive_re().is_match(&raw) || raw.starts_with('/')
}

fn drive_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z]:/").unwrap());
    &RE
}

/// Strips a Windows verbatim prefix (`\\?\C:\x` -> `C:\x`,
/// `\\?\UNC\srv\sh` -> `\\srv\sh`) that `std::fs::canonicalize` produces on
/// Windows, so physical paths compare against declared `C:\...` spellings.
/// Pure string operation; POSIX physical paths never start with `\\?\` and are
/// returned unchanged.
pub fn strip_verbatim_prefix(value: &str) -> String {
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        value.to_string()
    }
}

/// Physical path as a display string without any Windows verbatim prefix.
pub fn physical_path_string(path: &Path) -> String {
    strip_verbatim_prefix(&path.to_string_lossy())
}

/// Physical identity of an artifact that must already exist: the real
/// filesystem path with every symlink/junction/`..` followed. Resolution
/// failure is an error; there is deliberately NO lexical fallback.
///
/// This is a point-in-time resolution, not confinement: the filesystem can
/// change between this call and later reads/writes (TOCTOU).
pub fn resolve_physical_existing(path: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(path)
        .map_err(|e| format!("cannot resolve existing path {}: {e}", path.display()))
}

/// Physical identity of a receipt sidecar. The path must have a lexical
/// basename (`Path::file_name`), checked BEFORE any filesystem call, because
/// some platforms collapse a trailing `..` during lookup and would otherwise
/// resolve it to a directory. If the receipt exists (including as a link, even
/// a dangling one) it must canonicalize AND the canonical target must be a
/// regular file (a directory, or a directory link/junction, is rejected). If it
/// is absent (`NotFound`), its parent directory must canonicalize and the
/// result is the canonical parent joined with the basename. Any other failure
/// (missing parent, dangling link, non-directory parent, permission error, no
/// basename such as `..`) is an error; there is no lexical fallback.
///
/// Same point-in-time caveat as [`resolve_physical_existing`].
pub fn resolve_physical_receipt(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("receipt path {} has no resolvable basename", path.display()))?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let canonical = resolve_physical_existing(path)?;
            let meta = std::fs::metadata(&canonical).map_err(|e| {
                format!(
                    "cannot inspect resolved receipt target {}: {e}",
                    canonical.display()
                )
            })?;
            if !meta.is_file() {
                return Err(format!(
                    "receipt path {} resolves to a non-file target {}",
                    path.display(),
                    canonical.display()
                ));
            }
            Ok(canonical)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or_else(|| {
                    format!("receipt path {} has no resolvable parent", path.display())
                })?;
            let canonical_parent = std::fs::canonicalize(parent).map_err(|e| {
                format!(
                    "cannot resolve receipt parent directory {}: {e}",
                    parent.display()
                )
            })?;
            Ok(canonical_parent.join(name))
        }
        Err(e) => Err(format!(
            "cannot inspect receipt path {}: {e}",
            path.display()
        )),
    }
}

fn physical_norm(path: &Path, windows: bool) -> String {
    normalized_path(&physical_path_string(path), windows)
}

fn has_forbidden_part(normalized_paths: &[&str]) -> bool {
    normalized_paths.iter().any(|p| {
        p.split('/')
            .any(|part| FORBIDDEN_STORAGE_PARTS.contains(&part) || part.starts_with(".validator-"))
    })
}

/// Storage authorization for a handoff packet and its sidecar receipt.
///
/// Authority decisions (forbidden temp/cache storage, `.md` suffix, receipt
/// adjacency, receipt basename) are made on PHYSICAL paths: the existing
/// artifact is canonicalized; the receipt is canonicalized if it exists, else
/// its parent is canonicalized and the basename appended. If either cannot be
/// resolved, the result is an error (fail closed, no lexical fallback). The
/// forbidden-part check also still applies to the lexical spelling, so a path
/// that looked forbidden before still is.
///
/// The declared `Packet path` / `Receipt path` labels are metadata and may
/// match either the supplied lexical spelling or the physical path.
///
/// Canonicalization is point-in-time only; this makes no TOCTOU or
/// full-confinement claim.
pub fn storage_errors(
    text: &str,
    artifact: &Path,
    write_receipt: Option<&Path>,
    verify_receipt: Option<&Path>,
    windows: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    let declared_artifact =
        clean_path_value(&label_value(text, "**Packet path:**").unwrap_or_default());
    let declared_receipt =
        clean_path_value(&label_value(text, "**Receipt path:**").unwrap_or_default());
    let receipt_arg = write_receipt.or(verify_receipt);

    if !artifact.is_absolute() {
        errors.push("validator requires absolute handoff file path".to_string());
    }
    let physical_artifact = match resolve_physical_existing(artifact) {
        Ok(p) => p,
        Err(e) => {
            errors.push(format!(
                "handoff path cannot be resolved to a physical location: {e}"
            ));
            return errors;
        }
    };
    let lexical_artifact = normalized_path(&artifact.to_string_lossy(), windows);
    let physical_artifact_norm = physical_norm(&physical_artifact, windows);

    if !is_absolute_path(&declared_artifact) {
        errors.push("declared handoff packet path must be absolute".to_string());
    } else {
        let declared = normalized_path(&declared_artifact, windows);
        if declared != lexical_artifact && declared != physical_artifact_norm {
            errors.push("declared handoff packet path does not match validated file".to_string());
        }
    }

    if has_forbidden_part(&[lexical_artifact.as_str(), physical_artifact_norm.as_str()]) {
        errors.push("canonical handoff cannot use temporary/cache/review-run storage".to_string());
    }
    let suffix_is_md = physical_artifact
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase() == "md")
        .unwrap_or(false);
    if !suffix_is_md {
        errors.push("canonical handoff must be Markdown".to_string());
    }

    let Some(receipt_arg) = receipt_arg else {
        errors.push("validation must write or verify sidecar receipt".to_string());
        return errors;
    };
    if !receipt_arg.is_absolute() {
        errors.push("validator requires absolute receipt path".to_string());
    }
    let physical_receipt = match resolve_physical_receipt(receipt_arg) {
        Ok(p) => p,
        Err(e) => {
            errors.push(format!(
                "receipt path cannot be resolved to a physical location: {e}"
            ));
            return errors;
        }
    };
    let lexical_receipt = normalized_path(&receipt_arg.to_string_lossy(), windows);
    let physical_receipt_norm = physical_norm(&physical_receipt, windows);

    if !is_absolute_path(&declared_receipt) {
        errors.push("declared receipt path must be absolute".to_string());
    } else {
        let declared = normalized_path(&declared_receipt, windows);
        if declared != lexical_receipt && declared != physical_receipt_norm {
            errors.push(
                "declared receipt path does not match validator receipt argument".to_string(),
            );
        }
    }

    let receipt_parent = physical_receipt.parent().unwrap_or_else(|| Path::new(""));
    let artifact_parent = physical_artifact.parent().unwrap_or_else(|| Path::new(""));
    if physical_norm(receipt_parent, windows) != physical_norm(artifact_parent, windows) {
        errors.push("handoff receipt must be adjacent to canonical packet".to_string());
    }
    let stem = physical_artifact
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let expected_receipt = format!("{stem}.receipt.json");
    let receipt_name = physical_receipt
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if receipt_name != expected_receipt {
        errors.push(format!("handoff receipt must be named {expected_receipt}"));
    }
    if has_forbidden_part(&[lexical_receipt.as_str(), physical_receipt_norm.as_str()]) {
        errors.push("handoff receipt cannot use temporary/cache/review-run storage".to_string());
    }
    errors
}

pub const HEADINGS: &[&str] = &[
    "# COLD-START HANDOFF:",
    "## 0. Handoff Control",
    "## 1. Intent & Mission",
    "## 2. Current State",
    "## 3. Environment & Active Work",
    "## 4. Decisions, Invariants & User Corrections",
    "## 5. Artifacts & Evidence",
    "## 6. Failures, Dead Ends & Attempts",
    "## 7. Learnings, Gotchas & Landmines",
    "## 8. Open Loops & Context Gaps",
    "## 9. Safety, Authority & Boundaries",
    "## 10. Exact Resume Sequence",
    "## 11. State Verification & Invalidation",
    "## 12. First Output & Readback Contract",
    "## 13. Ready-to-Paste First Message",
    "## 14. Context Gap Report",
    "## 15. Handoff Author Gate",
];

pub const LABELS: &[&str] = &[
    "**Handoff ID:**",
    "**Created:**",
    "**Source task / chat:**",
    "**Target:**",
    "**Author:**",
    "**Receiver role:**",
    "**Proceed mode:**",
    "**Readiness:**",
    "**Handoff reason:**",
    "**Source evidence mode:**",
    "**Transcript evidence path:**",
    "**Source prefix receipt:**",
    "**Packet path:**",
    "**Receipt path:**",
    "**Original user intent verbatim:**",
    "**Underlying goal:**",
    "**Current objective:**",
    "**Definition of success:**",
    "**Out of scope:**",
    "**First responsibility:**",
    "**Must not do first:**",
    "**Phase:**",
    "**Completed:**",
    "**In progress:**",
    "**Blocked:**",
    "**Not started:**",
    "**Last action:**",
    "**Last observed result:**",
    "**Active goal / plan:**",
    "**Current hypothesis:**",
    "**Work type:**",
    "**Workspace / repo:**",
    "**Branch / version:**",
    "**Baseline revision:**",
    "**Dirty state:**",
    "**OS / shell:**",
    "**Tools / dependencies:**",
    "**Services / processes:**",
    "**Agents / tasks / threads:**",
    "**Scheduled work:**",
    "**Credentials / access:**",
    "**May do:**",
    "**Do not change:**",
    "**Do not run:**",
    "**Irreversible / production actions:**",
    "**Spend / external effects:**",
    "**Secrets handling:**",
    "**Reserved decisions:**",
    "**Verification command:**",
    "**Expected state:**",
    "**Invalidated by:**",
    "**Refresh action:**",
    "**Validator command:**",
    "**Receiver receipt check:**",
    "**First deliverable after readback:**",
    "**Gap report format:**",
    "**Gap summary:**",
    "**Safe-to-proceed scope:**",
    "**Fatal recovery owner:**",
    "**Exact recovery sequence:**",
];

pub const STEP_LABELS: &[&str] = &[
    "**Owner:**",
    "**Working directory / system:**",
    "**Exact action:**",
    "**Expected result:**",
    "**Evidence path:**",
    "**Timeout / retry:**",
    "**If failure:**",
    "**Depends on:**",
];

const GENERIC: &[&str] = &[
    "",
    "value",
    "example",
    "placeholder",
    "fixture-value",
    "todo",
    "tbd",
    "n/a",
    "none",
];
const ENUM_VALUES: &[&str] = &[
    "READY",
    "READY_WITH_GAPS",
    "NOT_READY",
    "IMMEDIATE",
    "READBACK_ONLY",
    "REVIEW_ONLY",
    "DECISION",
    "CODE",
    "DOCUMENT",
    "RESEARCH",
    "OPERATIONS",
    "MIXED",
    "LOCKED",
    "ACTIVE_ASSUMPTION",
    "REVISIT_ON",
    "FATAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "NONE",
];

fn banned_patterns() -> &'static [(&'static str, Regex)] {
    static RE: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
        vec![
            ("old-chat dependency", Regex::new(r"(?i)\b(as discussed|see above|previous chat|you already know|prior[- ](?:thread|chat|conversation) context|earlier[- ](?:thread|chat|conversation)|inherited context|remembered state|implicit credentials?|(?:old|earlier|prior)[- ](?:messages?|session|history))\b").unwrap()),
            ("orphan continuation", Regex::new(r"(?i)\b(continue where we left off|just continue|usual constraints apply)\b").unwrap()),
            ("weak gap handling", Regex::new(r"(?i)\b(ask me if anything is unclear|catch up on)\b").unwrap()),
            ("unfinished marker", Regex::new(r"\b(TODO|TBD|TK)\b").unwrap()),
        ]
    });
    &RE
}

fn secret_patterns() -> &'static [(&'static str, Regex)] {
    static RE: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
        vec![
            ("OpenAI-like key", Regex::new(r"\bsk-[A-Za-z0-9_-]{20,}\b").unwrap()),
            ("GitHub token", Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap()),
            ("Slack token", Regex::new(r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b").unwrap()),
            ("AWS access key", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            ("private key", Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()),
            ("literal secret assignment", Regex::new(r#"(?i)\b(password|api[_-]?key|secret|token)\s*[:=]\s*[`"']?[A-Za-z0-9+/=_-]{12,}"#).unwrap()),
            ("authorization header", Regex::new(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}").unwrap()),
            ("bearer credential", Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}").unwrap()),
        ]
    });
    &RE
}

fn step_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^### Resume Step\s+\d+\s+—\s+.+$").unwrap());
    &RE
}
fn path_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?:[A-Za-z]:[\\/]|/)[^\s`|]+").unwrap());
    &RE
}
fn action_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(run|read|search|inspect|verify|capture|compare|resume|execute|open|check|record|load|query|test)\b").unwrap()
    });
    &RE
}
fn placeholder_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{[^{}\n]+\}\}").unwrap());
    &RE
}

/// Minimal whitespace tokenizer for a single documented validator command
/// line. Single/double quotes group a token (no escapes; backslashes are
/// literal so Windows paths survive). Returns `None` on an unterminated quote.
/// This is deliberately NOT a shell parser: operators such as `;`, `&&`, `|`
/// are just ordinary tokens and therefore fail the exact-shape checks below.
fn split_command_tokens(command: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    for c in command.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    current.push(c);
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                    in_token = true;
                } else if c.is_whitespace() {
                    if in_token {
                        tokens.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                } else {
                    current.push(c);
                    in_token = true;
                }
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}

fn token_basename(token: &str) -> String {
    token
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Legacy interpreter executable kinds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Interpreter {
    /// `python`, `python<digits>`, `python<digits>.<digits>` (optional `.exe`).
    Python,
    /// Windows `py` launcher: `py` / `py.exe`.
    PyLauncher,
}

/// Classifies the executable token by basename (case-insensitive, optional
/// single `.exe`, any directory prefix). Malformed names such as `python.`,
/// `python3.`, `python..`, `python3.12.1`, `python3x` are not interpreters.
fn interpreter_kind(token: &str) -> Option<Interpreter> {
    let base = token_basename(token).to_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    if base == "py" {
        return Some(Interpreter::PyLauncher);
    }
    let version = base.strip_prefix("python")?;
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    let ok = match version.split_once('.') {
        None => version.is_empty() || digits(version),
        Some((major, minor)) => digits(major) && digits(minor),
    };
    ok.then_some(Interpreter::Python)
}

/// Exact `py` launcher selector token: `-2` or `-3`, optionally `.<digits>`,
/// optionally `-32`, `-64`, or `-arm64` (e.g. `-3`, `-3.11`, `-3.12-64`).
/// Rejects `-0`, `-0p`, `-V:...`, `--list`, `-3.`, `-4`, `-3-16`, etc.
fn is_py_launcher_selector(token: &str) -> bool {
    let Some(body) = token.strip_prefix('-') else {
        return false;
    };
    let (version, arch) = match body.split_once('-') {
        Some((v, a)) => (v, Some(a)),
        None => (body, None),
    };
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    let mut parts = version.split('.');
    let major_ok = matches!(parts.next(), Some("2" | "3"));
    let minor_ok = parts.next().map_or(true, digits);
    major_ok
        && minor_ok
        && parts.next().is_none()
        && arch.map_or(true, |a| matches!(a, "32" | "64" | "arm64"))
}

/// Allow-list for interpreter options after the (optional) launcher selector
/// and before the script: only no-argument file-mode switches, single letters
/// from `bBdEIOPqRsSuv`, optionally clustered (`-IB`, `-bb`, `-OO`). Everything
/// else is rejected, notably `-c`/`-m` (and attached forms like `-cprint(1)`,
/// `-mpkg`, `-Ic`), argument-taking `-W`/`-X`, `-V`/`-h` (which do not run the
/// script), `-i`, `-x`, `-`, `--`, every `--long` option, and ANY launcher
/// selector or `-0` form: a selector is not a generic repeatable flag, so it is
/// only legal immediately after `py` (see [`validator_args`]).
fn python_flag_is_supported(token: &str) -> bool {
    let Some(body) = token.strip_prefix('-') else {
        return false;
    };
    !body.is_empty() && body.chars().all(|c| "bBdEIOPqRsSuv".contains(c))
}

/// Returns the argument tokens after the validator program if (and only if)
/// the command starts with a recognized validator invocation:
/// - native: `legion script handoff/validate-handoff ...`
/// - legacy FILE-MODE, exact grammar:
///   `[<python-exe> | <py-exe> [SELECTOR]] [NOARG_FLAG...] <path>/validate-handoff.py ...`
///   - `<python-exe>`: basename `python`, `python<digits>`, or
///     `python<digits>.<digits>` (optional `.exe`/directory);
///   - `<py-exe>`: `py`/`py.exe`; only it may carry at most ONE selector,
///     and only immediately after the executable (see
///     [`is_py_launcher_selector`]; the real launcher honors only a first-arg
///     control, and `-0`/`--list`/version/help print and exit);
///   - then only known no-argument flags ([`python_flag_is_supported`]);
///   - then the validator script by exact basename.
///   Any other option returns `None`, because it could stop the script from
///   being what is actually executed.
fn validator_args(tokens: &[String]) -> Option<&[String]> {
    if let [a, b, c, rest @ ..] = tokens {
        if a == "legion" && b == "script" && c == "handoff/validate-handoff" {
            return Some(rest);
        }
    }
    let mut idx = 0;
    if let Some(kind) = tokens.first().and_then(|t| interpreter_kind(t)) {
        idx = 1;
        if kind == Interpreter::PyLauncher
            && tokens.get(idx).is_some_and(|t| is_py_launcher_selector(t))
        {
            idx += 1;
        }
        while let Some(token) = tokens.get(idx) {
            if !token.starts_with('-') {
                break;
            }
            if !python_flag_is_supported(token) {
                return None;
            }
            idx += 1;
        }
    }
    let script = tokens.get(idx)?;
    if token_basename(script) == "validate-handoff.py" {
        Some(&tokens[idx + 1..])
    } else {
        None
    }
}

fn same_bound_path(token: &str, declared: &str) -> bool {
    let token = clean_path_value(token);
    let declared = clean_path_value(declared);
    !declared.is_empty() && normalized_path(&token, false) == normalized_path(&declared, false)
}

/// True iff `command` is exactly one validator invocation (native or legacy)
/// whose only arguments are the declared packet path and `flag` followed by
/// the declared receipt path (packet-first or flag-first). Any extra token
/// (including `--template-self-check`, a second flag, or shell operators),
/// similarly named program, wrong flag, or unbound/different path is rejected.
/// Path equality is lexical metadata comparison, not filesystem identity.
fn command_binds_validator(command: &str, flag: &str, packet: &str, receipt: &str) -> bool {
    let Some(tokens) = split_command_tokens(command) else {
        return false;
    };
    let Some(args) = validator_args(&tokens) else {
        return false;
    };
    match args {
        [p, f, r] if f == flag => same_bound_path(p, packet) && same_bound_path(r, receipt),
        [f, r, p] if f == flag => same_bound_path(p, packet) && same_bound_path(r, receipt),
        _ => false,
    }
}

pub fn label_value(text: &str, label: &str) -> Option<String> {
    let escaped = regex::escape(label);
    let re = Regex::new(&format!(r"(?m)^-\s+{escaped}\s*(.*)$")).ok()?;
    re.captures(text).map(|c| c[1].trim().to_string())
}

pub fn concrete(value: &str) -> bool {
    let raw = value.trim().trim_matches('`');
    if ENUM_VALUES.contains(&raw) {
        return true;
    }
    let normalized = raw.to_lowercase();
    normalized.chars().count() >= 8 && !GENERIC.contains(&normalized.as_str())
}

pub fn fenced_after(text: &str, label: &str) -> Option<String> {
    let escaped = regex::escape(label);
    let re = Regex::new(&format!(r"(?s){escaped}\s*\n+\s*```[^\n]*\n(.*?)\n```")).ok()?;
    re.captures(text).map(|c| c[1].trim().to_string())
}

pub fn table_rows(text: &str, start: &str, end: &str) -> Vec<Vec<String>> {
    let Some(left) = text.find(start) else {
        return Vec::new();
    };
    let Some(right_rel) = text[left + start.len()..].find(end) else {
        return Vec::new();
    };
    let right = left + start.len() + right_rel;
    let mut rows = Vec::new();
    let sep_re = Regex::new(r"^:?-{3,}:?$").unwrap();
    for line in text[left..right].lines() {
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect();
        if cells.iter().all(|c| sep_re.is_match(c)) {
            continue;
        }
        rows.push(cells);
    }
    rows
}

pub fn table_errors(name: &str, rows: &[Vec<String>], width: usize, template: bool) -> Vec<String> {
    if rows.len() < 2 {
        return vec![format!("{name} requires at least one data row")];
    }
    let mut errors = Vec::new();
    for (row_index, row) in rows[1..].iter().enumerate() {
        let row_index = row_index + 1;
        if row.len() != width {
            errors.push(format!("{name} row {row_index} must contain {width} cells"));
            continue;
        }
        if !template {
            for (cell_index, cell) in row.iter().enumerate() {
                let cell_index = cell_index + 1;
                if !concrete(cell) {
                    errors.push(format!(
                        "{name} row {row_index} cell {cell_index} is too vague"
                    ));
                }
            }
        }
    }
    errors
}

pub fn ordered_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut cursor: i64 = -1;
    for &heading in HEADINGS {
        match text.find(heading) {
            None => errors.push(format!("missing heading: {heading}")),
            Some(index) => {
                let index = index as i64;
                if index <= cursor {
                    errors.push(format!("heading out of order: {heading}"));
                } else {
                    cursor = index;
                }
            }
        }
    }
    errors
}

pub fn resume_errors(text: &str, template: bool) -> Vec<String> {
    let matches: Vec<_> = step_re().find_iter(text).collect();
    if matches.len() < 3 {
        return vec!["resume sequence requires at least 3 steps".to_string()];
    }
    let mut errors = Vec::new();
    let section_end = text
        .find("## 11. State Verification & Invalidation")
        .unwrap_or(text.len());
    for (index, m) in matches.iter().enumerate() {
        let end = matches
            .get(index + 1)
            .map(|n| n.start())
            .unwrap_or(section_end);
        let block = &text[m.start()..end];
        let name = m.as_str();
        for &label in STEP_LABELS {
            if !block.contains(label) {
                errors.push(format!("{name} missing label: {label}"));
            }
        }
        let action = fenced_after(block, "**Exact action:**");
        if action.is_none() {
            errors.push(format!("{name} lacks fenced exact action"));
        }
        if template {
            continue;
        }
        for &label in STEP_LABELS {
            if label == "**Exact action:**" {
                continue;
            }
            let value = label_value(block, label).unwrap_or_default();
            if !concrete(&value) {
                errors.push(format!("{name} has non-concrete value: {label}"));
            }
        }
        let action_ok = action
            .as_ref()
            .map(|a| concrete(a) && action_re().is_match(a))
            .unwrap_or(false);
        if !action_ok {
            errors.push(format!("{name} exact action is not executable/actionable"));
        }
        for label in ["**Working directory / system:**", "**Evidence path:**"] {
            let value = label_value(block, label).unwrap_or_default();
            if !path_re().is_match(&value) {
                errors.push(format!("{name} {label} lacks explicit path"));
            }
        }
        let timeout_value = label_value(block, "**Timeout / retry:**").unwrap_or_default();
        if !timeout_value.chars().any(|c| c.is_ascii_digit()) {
            errors.push(format!("{name} timeout/retry lacks numeric bound"));
        }
    }
    errors
}

pub fn validate(text: &str, template: bool) -> Vec<String> {
    let mut errors = ordered_errors(text);
    for &label in LABELS {
        match label_value(text, label) {
            None => errors.push(format!("missing label: {label}")),
            Some(value) => {
                let is_optional_empty = matches!(
                    label,
                    "**Verification command:**"
                        | "**Validator command:**"
                        | "**Receiver receipt check:**"
                );
                if value.is_empty() && !is_optional_empty {
                    errors.push(format!("empty value: {label}"));
                } else if !template
                    && GENERIC.contains(&value.trim().trim_matches('`').to_lowercase().as_str())
                {
                    errors.push(format!("generic filler value: {label}"));
                }
            }
        }
    }

    errors.extend(resume_errors(text, template));

    let tables: [(&str, &str, &str, usize); 5] = [
        (
            "decision log",
            "## 4. Decisions, Invariants & User Corrections",
            "## 5. Artifacts & Evidence",
            5,
        ),
        (
            "artifact map",
            "## 5. Artifacts & Evidence",
            "## 6. Failures, Dead Ends & Attempts",
            6,
        ),
        (
            "failure map",
            "## 6. Failures, Dead Ends & Attempts",
            "## 7. Learnings, Gotchas & Landmines",
            7,
        ),
        (
            "gotcha map",
            "## 7. Learnings, Gotchas & Landmines",
            "## 8. Open Loops & Context Gaps",
            4,
        ),
        (
            "gap map",
            "## 8. Open Loops & Context Gaps",
            "## 9. Safety, Authority & Boundaries",
            6,
        ),
    ];
    let mut parsed: std::collections::BTreeMap<&str, Vec<Vec<String>>> =
        std::collections::BTreeMap::new();
    for (name, start, end, width) in tables {
        let rows = table_rows(text, start, end);
        errors.extend(table_errors(name, &rows, width, template));
        parsed.insert(name, rows);
    }

    if !template {
        let readiness = label_value(text, "**Readiness:**").unwrap_or_default();
        let readiness = readiness.trim_matches('`');
        if !["READY", "READY_WITH_GAPS", "NOT_READY"].contains(&readiness) {
            errors.push("Readiness must be READY, READY_WITH_GAPS, or NOT_READY".to_string());
        }
        let proceed = label_value(text, "**Proceed mode:**").unwrap_or_default();
        let proceed = proceed.trim_matches('`');
        if !["IMMEDIATE", "READBACK_ONLY", "REVIEW_ONLY", "DECISION"].contains(&proceed) {
            errors.push("invalid Proceed mode".to_string());
        }
        let work_type = label_value(text, "**Work type:**").unwrap_or_default();
        let work_type = work_type.trim_matches('`');
        if !["CODE", "DOCUMENT", "RESEARCH", "OPERATIONS", "MIXED"].contains(&work_type) {
            errors.push("invalid Work type".to_string());
        }
        let source_mode = label_value(text, "**Source evidence mode:**").unwrap_or_default();
        let source_mode = source_mode.trim_matches('`').to_string();
        let evidence_path = label_value(text, "**Transcript evidence path:**").unwrap_or_default();
        let source_receipt = label_value(text, "**Source prefix receipt:**").unwrap_or_default();
        if !["TRANSCRIPT_INGEST", "LIVE_CONTEXT"].contains(&source_mode.as_str()) {
            errors
                .push("Source evidence mode must be TRANSCRIPT_INGEST or LIVE_CONTEXT".to_string());
        }
        if source_mode == "TRANSCRIPT_INGEST" {
            if !path_re().is_match(&evidence_path) {
                errors.push("TRANSCRIPT_INGEST requires absolute Legion context path".to_string());
            }
            let upper = source_receipt.to_uppercase();
            for token in [
                "PLATFORM:",
                "SESSION_ID:",
                "CUTOFF_BYTES:",
                "SHA256:",
                "PARSER_VERSION:",
            ] {
                if !upper.contains(token) {
                    errors.push(format!(
                        "TRANSCRIPT_INGEST source prefix receipt missing {token}"
                    ));
                }
            }
            if !Regex::new(r"(?i)\bSHA256:[0-9a-f]{64}\b")
                .unwrap()
                .is_match(&source_receipt)
            {
                errors.push(
                    "TRANSCRIPT_INGEST source prefix receipt requires 64-hex SHA256".to_string(),
                );
            }
            if !Regex::new(r"(?i)\bCUTOFF_BYTES:[1-9]\d*\b")
                .unwrap()
                .is_match(&source_receipt)
            {
                errors.push(
                    "TRANSCRIPT_INGEST source prefix receipt requires positive cutoff".to_string(),
                );
            }
        } else {
            let na_re = Regex::new(r"(?i)^NOT_APPLICABLE:\s*\S").unwrap();
            if !na_re.is_match(&evidence_path) {
                errors.push(
                    "LIVE_CONTEXT transcript evidence path requires NOT_APPLICABLE reason"
                        .to_string(),
                );
            }
            if !na_re.is_match(&source_receipt) {
                errors.push(
                    "LIVE_CONTEXT source prefix receipt requires NOT_APPLICABLE reason".to_string(),
                );
            }
        }

        let mut severities: Vec<String> = Vec::new();
        if let Some(rows) = parsed.get("gap map") {
            for row in rows.iter().skip(1) {
                if row.len() == 6 {
                    let severity = row[1].trim_matches('`').to_string();
                    if !["FATAL", "HIGH", "MEDIUM", "LOW", "NONE"].contains(&severity.as_str()) {
                        errors.push(format!("invalid gap severity: {severity}"));
                    }
                    severities.push(severity);
                }
            }
        }
        if readiness == "READY" && severities.iter().any(|s| s == "FATAL" || s == "HIGH") {
            errors.push("READY cannot contain FATAL or HIGH gap".to_string());
        }
        if readiness == "NOT_READY" && !severities.iter().any(|s| s == "FATAL") {
            errors.push("NOT_READY requires FATAL gap".to_string());
        }
        if readiness == "READY_WITH_GAPS" && severities.iter().all(|s| s == "NONE") {
            errors.push("READY_WITH_GAPS requires declared gap".to_string());
        }
        if readiness == "READY_WITH_GAPS" && severities.iter().any(|s| s == "FATAL") {
            errors.push("READY_WITH_GAPS cannot contain FATAL gap; use NOT_READY".to_string());
        }

        let verification = fenced_after(text, "**Verification command:**");
        let verification_ok = verification
            .as_ref()
            .map(|v| concrete(v) && action_re().is_match(v))
            .unwrap_or(false);
        if !verification_ok {
            errors.push("state verification lacks executable fenced command/action".to_string());
        }
        let validator_command = fenced_after(text, "**Validator command:**").unwrap_or_default();
        let receiver_command =
            fenced_after(text, "**Receiver receipt check:**").unwrap_or_default();
        let declared_packet =
            clean_path_value(&label_value(text, "**Packet path:**").unwrap_or_default());
        let declared_receipt =
            clean_path_value(&label_value(text, "**Receipt path:**").unwrap_or_default());
        for (label, command, flag) in [
            ("Validator command", &validator_command, "--write-receipt"),
            (
                "Receiver receipt check",
                &receiver_command,
                "--verify-receipt",
            ),
        ] {
            if !command_binds_validator(command, flag, &declared_packet, &declared_receipt) {
                errors.push(format!(
                    "{label} must execute `legion script handoff/validate-handoff` \
                     (or legacy validate-handoff.py) with bound packet/receipt paths and {flag}"
                ));
            }
        }
        for label in [
            "**Packet path:**",
            "**Receipt path:**",
            "**Workspace / repo:**",
        ] {
            let value = label_value(text, label).unwrap_or_default();
            if !path_re().is_match(&value) {
                errors.push(format!("{label} lacks explicit path"));
            }
        }
        let first_start = text
            .find("## 13. Ready-to-Paste First Message")
            .unwrap_or(0);
        let first_end = text.find("## 14. Context Gap Report").unwrap_or(text.len());
        let first_message = if first_end > first_start {
            &text[first_start..first_end]
        } else {
            ""
        };
        if !first_message.contains("READBACK") || !first_message.contains("Proceed mode") {
            errors.push("first message must require READBACK + Proceed mode".to_string());
        }
    }

    let author_start = text
        .find("## 15. Handoff Author Gate")
        .unwrap_or(text.len());
    let author = &text[author_start..];
    if !template {
        if placeholder_re().is_match(text) {
            errors.push("unfilled placeholder remains".to_string());
        }
        if author.contains("- [ ]") {
            errors.push("handoff author gate contains unchecked item".to_string());
        }
        if author.matches("- [x]").count() < 18 {
            errors.push("handoff author gate requires 18 checked items".to_string());
        }
    }

    for (name, pattern) in banned_patterns() {
        if let Some(m) = pattern.find(text) {
            errors.push(format!("{name}: forbidden phrase '{}'", m.as_str()));
        }
    }
    if !template {
        for (name, pattern) in secret_patterns() {
            if pattern.is_match(text) {
                errors.push(format!("possible secret detected: {name}"));
            }
        }
    }

    let mut unique: Vec<String> = errors
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    unique.sort();
    unique
}

/// Convenience: absolute-path variant of `normalized_path` for callers that
/// already hold a `PathBuf` (mirrors `Path.resolve()` call sites in Python).
pub fn normalized_pathbuf(value: &Path, windows: bool) -> String {
    normalized_path(&value.to_string_lossy(), windows)
}

#[allow(dead_code)]
fn _unused(_p: PathBuf) {}

/// Test-only scratch directories and link helpers shared with `cli.rs` tests.
///
/// Scratch roots live under the test executable's directory (inside the cargo
/// target dir), NOT the OS temp dir, because `tmp`/`temp` path parts are
/// forbidden storage and would make "valid path" cases fail on Linux. A root
/// that still contains a forbidden part panics loudly rather than passing.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{normalized_path, strip_verbatim_prefix, FORBIDDEN_STORAGE_PARTS};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub struct TestRoot(pub PathBuf);

    impl TestRoot {
        pub fn new(label: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let exe = std::env::current_exe().expect("current_exe");
            let base = exe
                .parent()
                .expect("test exe has a parent dir")
                .join("l1b-path-identity-tests");
            let dir = base.join(format!(
                "{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create scratch root");
            let canonical = std::fs::canonicalize(&dir).expect("canonicalize scratch root");
            let canonical = PathBuf::from(strip_verbatim_prefix(&canonical.to_string_lossy()));
            let norm = normalized_path(&canonical.to_string_lossy(), cfg!(windows));
            let bad = norm.split('/').find(|part| {
                FORBIDDEN_STORAGE_PARTS.contains(part) || part.starts_with(".validator-")
            });
            assert!(
                bad.is_none(),
                "test scratch root {norm} contains forbidden storage part {bad:?}; \
                 run tests with a target dir outside temp/cache locations"
            );
            TestRoot(canonical)
        }

        pub fn join(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn write_file(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().expect("file has parent")).expect("create parent");
        std::fs::write(path, body).expect("write file");
    }

    /// Directory symlink (Unix / Windows symlink) with a Windows junction
    /// fallback when symlink privilege is unavailable. Panics if no link can be
    /// created, so a platform that cannot link fails visibly instead of passing.
    pub fn link_dir(link: &Path, target: &Path) {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).expect("create directory symlink");
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_dir(target, link).is_err() {
                let out = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(link)
                    .arg(target)
                    .output()
                    .expect("spawn cmd for mklink /J");
                assert!(
                    out.status.success(),
                    "cannot create directory symlink or junction: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (link, target);
            panic!("directory links unsupported on this platform");
        }
    }

    #[cfg(unix)]
    pub fn link_file(link: &Path, target: &Path) {
        std::os::unix::fs::symlink(target, link).expect("create file symlink");
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{link_dir, write_file, TestRoot};
    use super::*;

    const WIN: bool = cfg!(windows);
    const FORBIDDEN_ARTIFACT: &str =
        "canonical handoff cannot use temporary/cache/review-run storage";
    const FORBIDDEN_RECEIPT: &str = "handoff receipt cannot use temporary/cache/review-run storage";
    const NOT_ADJACENT: &str = "handoff receipt must be adjacent to canonical packet";

    fn text_for(packet: &Path, receipt: &Path) -> String {
        format!(
            "- **Packet path:** `{}`\n- **Receipt path:** `{}`\n",
            packet.display(),
            receipt.display()
        )
    }

    fn check(artifact: &Path, receipt: &Path) -> Vec<String> {
        storage_errors(
            &text_for(artifact, receipt),
            artifact,
            Some(receipt),
            None,
            WIN,
        )
    }

    fn lexical_has_forbidden(path: &Path) -> bool {
        normalized_path(&path.to_string_lossy(), WIN)
            .split('/')
            .any(|p| FORBIDDEN_STORAGE_PARTS.contains(&p))
    }

    #[test]
    fn normalized_path_is_lexical_metadata_only() {
        assert_eq!(normalized_path("/a/b/../c/./d/", false), "/a/c/d");
        // Drive-letter branch: separators are unified, the trailing `/` is
        // trimmed, and (with `windows`) case is folded. `.`/`..` are NOT
        // collapsed here (historical metadata behavior); only the non-drive
        // branch collapses them.
        assert_eq!(
            normalized_path(r"C:\Users\X\..\Y\", true),
            "c:/users/x/../y"
        );
        assert_eq!(
            normalized_path(r"C:\Users\X\..\Y\", false),
            "C:/Users/X/../Y"
        );

        // A link spelling normalizes to itself; the helper never follows it.
        let root = TestRoot::new("lexical-only");
        std::fs::create_dir_all(root.join("real")).unwrap();
        link_dir(&root.join("stable"), &root.join("real"));
        let link_path = root.join("stable");
        let normalized = normalized_path(&link_path.to_string_lossy(), WIN);
        assert!(normalized.ends_with("/stable"), "{normalized}");
        assert!(!normalized.contains("/real"), "{normalized}");
        // Physical resolution, by contrast, does follow the link.
        let physical = resolve_physical_existing(&link_path).unwrap();
        assert!(
            physical_path_string(&physical).ends_with("real"),
            "{physical:?}"
        );
    }

    const PKT: &str = "<package-root>/skills/handoff/examples/validated-forward-test.md";
    const RCP: &str = "<package-root>/skills/handoff/examples/validated-forward-test.receipt.json";
    const NATIVE: &str = "legion script handoff/validate-handoff";

    #[test]
    fn documented_native_commands_bind_packet_receipt_and_flag() {
        // Exact strings from skills/handoff examples/SKILL/manual.
        let write = format!("{NATIVE} {PKT} --write-receipt {RCP}");
        let verify = format!("{NATIVE} {PKT} --verify-receipt {RCP}");
        assert!(command_binds_validator(&write, "--write-receipt", PKT, RCP));
        assert!(command_binds_validator(
            &verify,
            "--verify-receipt",
            PKT,
            RCP
        ));
        // Same through the real fenced extraction used by validate().
        let text = format!("- **Validator command:**\n\n```text\n{write}\n```\n");
        let extracted = fenced_after(&text, "**Validator command:**").unwrap();
        assert!(command_binds_validator(
            &extracted,
            "--write-receipt",
            PKT,
            RCP
        ));
    }

    #[test]
    fn legacy_python_invocation_is_still_accepted() {
        for prefix in [
            "python3 scripts/validate-handoff.py",
            "python -I /x/scripts/validate-handoff.py",
            "py C:\\x\\validate-handoff.py",
            "/usr/bin/python3.12 -I -B ./validate-handoff.py",
            "./validate-handoff.py",
        ] {
            let cmd = format!("{prefix} {PKT} --verify-receipt {RCP}");
            assert!(
                command_binds_validator(&cmd, "--verify-receipt", PKT, RCP),
                "{cmd}"
            );
        }
        // Flag-first argument order is also a valid argparse spelling.
        let cmd = format!("{NATIVE} --write-receipt {RCP} {PKT}");
        assert!(command_binds_validator(&cmd, "--write-receipt", PKT, RCP));
    }

    #[test]
    fn supported_python_file_mode_flags_and_launcher_selectors_are_accepted() {
        for prefix in [
            "python3 validate-handoff.py",
            "python3 -I validate-handoff.py",
            "python3 -B -s validate-handoff.py",
            "python3 -IB validate-handoff.py",
            "python3 -bb -OO -vv -u -E -S -q -R -P -d validate-handoff.py",
            "python3.12.exe -I validate-handoff.py",
            "py validate-handoff.py",
            "py -3 validate-handoff.py",
            "py -3.12 -I validate-handoff.py",
            "py -3.12-64 validate-handoff.py",
            "py -3-32 validate-handoff.py",
            "PY.EXE -3.13-arm64 -B C:\\x\\validate-handoff.py",
        ] {
            let cmd = format!("{prefix} {PKT} --write-receipt {RCP}");
            assert!(
                command_binds_validator(&cmd, "--write-receipt", PKT, RCP),
                "must accept: {cmd}"
            );
        }
    }

    #[test]
    fn python_code_module_and_unsupported_options_are_rejected() {
        // `-c`/`-m` make Python run something other than the script, so the
        // trailing `validate-handoff.py` would just be an argv string.
        for prefix in [
            "python3 -c validate-handoff.py",
            "python3 -m validate-handoff.py",
            "python3 -I -c validate-handoff.py",
            "python3 -c -I validate-handoff.py",
            "python3 -cprint(1) validate-handoff.py",
            "python3 -mhttp.server validate-handoff.py",
            "python3 -Ic validate-handoff.py",
            "python3 -Im validate-handoff.py",
            "python3 -Bc validate-handoff.py",
            "python3 -mI validate-handoff.py",
            // argument-taking options, separated and attached
            "python3 -W error validate-handoff.py",
            "python3 -Werror validate-handoff.py",
            "python3 -X utf8 validate-handoff.py",
            "python3 -Xutf8 validate-handoff.py",
            "python3 -IWignore validate-handoff.py",
            // options that do not run the script, or change mode
            "python3 -V validate-handoff.py",
            "python3 --version validate-handoff.py",
            "python3 -h validate-handoff.py",
            "python3 --help validate-handoff.py",
            "python3 -i validate-handoff.py",
            "python3 -x validate-handoff.py",
            "python3 -- validate-handoff.py",
            "python3 - validate-handoff.py",
            "python3 --check-hash-based-pycs always validate-handoff.py",
            // launcher selectors are only valid for `py`, and must be well-formed
            "python3 -3 validate-handoff.py",
            "py -3. validate-handoff.py",
            "py -3.12.1 validate-handoff.py",
            "py -3-16 validate-handoff.py",
            "py -V:3.12 validate-handoff.py",
            "py -c validate-handoff.py",
            "py -3 -m validate-handoff.py",
        ] {
            let cmd = format!("{prefix} {PKT} --write-receipt {RCP}");
            assert!(
                !command_binds_validator(&cmd, "--write-receipt", PKT, RCP),
                "must reject: {cmd}"
            );
        }
    }

    #[test]
    fn interpreter_basename_grammar_is_exact() {
        for exe in [
            "python",
            "python3",
            "python3.12",
            "python3.12.exe",
            "PYTHON3.13.EXE",
            "/usr/bin/python3",
            "C:\\Python313\\python.exe",
            "py",
            "PY.EXE",
            "C:\\Windows\\py.exe",
        ] {
            let cmd = format!("{exe} validate-handoff.py {PKT} --write-receipt {RCP}");
            assert!(
                command_binds_validator(&cmd, "--write-receipt", PKT, RCP),
                "must accept: {cmd}"
            );
        }
        for exe in [
            "python.",
            "python3.",
            "python..",
            "python.3",
            "python3..12",
            "python3.12.",
            "python3.12.1",
            "python3.x",
            "python3x",
            "pythonw",
            "python3.exe.exe",
            "py3",
            "py.",
            "pyy",
            "/usr/bin/python3.",
        ] {
            let cmd = format!("{exe} validate-handoff.py {PKT} --write-receipt {RCP}");
            assert!(
                !command_binds_validator(&cmd, "--write-receipt", PKT, RCP),
                "must reject: {cmd}"
            );
        }
    }

    #[test]
    fn py_launcher_selector_is_single_and_immediately_after_executable() {
        for prefix in [
            "py -3.11 -I",
            "py -3",
            "py -2",
            "py -2.7",
            "py -3.11-64 -B -s",
            "py -3-32",
            "py.exe -3.13-arm64 -IB",
            "C:\\Windows\\py.exe -3.12 -E",
        ] {
            let cmd = format!("{prefix} validate-handoff.py {PKT} --write-receipt {RCP}");
            assert!(
                command_binds_validator(&cmd, "--write-receipt", PKT, RCP),
                "must accept: {cmd}"
            );
        }
        for prefix in [
            // launcher list/info modes print and exit; never run the script
            "py -0",
            "py -0p",
            "py --list",
            "py --list-paths",
            "py -V",
            "py --version",
            "py -h",
            "py --help",
            "py -V:3.12",
            // selector after a flag (launcher only honors the first argument)
            "py -I -3.11",
            "py -B -3",
            // duplicate / multiple selectors
            "py -3.12 -3.11",
            "py -3 -3",
            "py -2 -3",
            "py -3.11 -I -3.12",
            // selector grammar: only 2/3, optional .digits, optional arch
            "py -4",
            "py -1",
            "py -3.",
            "py -3.x",
            "py -3.11.2",
            "py -3-",
            "py -3-16",
            "py -3.11-x64",
            // selectors are not legal for non-launcher interpreters
            "python3 -3",
            "python3 -3.11",
            "python3 -I -3.11",
            // malformed interpreter, even with otherwise valid options
            "python. -I",
            "python3. -I",
            "python.. -I",
            "pythonmalformed -I",
        ] {
            let cmd = format!("{prefix} validate-handoff.py {PKT} --write-receipt {RCP}");
            assert!(
                !command_binds_validator(&cmd, "--write-receipt", PKT, RCP),
                "must reject: {cmd}"
            );
        }
    }

    #[test]
    fn quoted_paths_with_spaces_bind_exactly() {
        let cmd = format!("{NATIVE} \"/a b/h.md\" --write-receipt '/a b/h.receipt.json'");
        assert!(command_binds_validator(
            &cmd,
            "--write-receipt",
            "/a b/h.md",
            "/a b/h.receipt.json"
        ));
    }

    #[test]
    fn unrelated_similar_or_unbound_commands_are_rejected() {
        let bad = [
            // unrelated program
            format!("echo {PKT} --write-receipt {RCP}"),
            format!("legion script handoff/other {PKT} --write-receipt {RCP}"),
            format!("legion script other/validate-handoff {PKT} --write-receipt {RCP}"),
            // similar program names
            format!("legion script handoff/validate-handoff2 {PKT} --write-receipt {RCP}"),
            format!("legion script handoff/validate-handoff.py {PKT} --write-receipt {RCP}"),
            format!("python3 not-validate-handoff.py {PKT} --write-receipt {RCP}"),
            format!("python3 validate-handoff.py.bak {PKT} --write-receipt {RCP}"),
            format!("pythonx validate-handoff.py {PKT} --write-receipt {RCP}"),
            // name only appears as an argument / in a larger string
            format!("echo validate-handoff.py {PKT} --write-receipt {RCP}"),
            format!("legion script handoff/validate-handoff-extra {PKT} --write-receipt {RCP}"),
            // missing bound paths
            format!("{NATIVE} --write-receipt {RCP}"),
            format!("{NATIVE} {PKT} --write-receipt"),
            format!("{NATIVE} {PKT}"),
            NATIVE.to_string(),
            String::new(),
            // different paths / suffix-extended path (no substring matching)
            format!("{NATIVE} {PKT}.bak --write-receipt {RCP}"),
            format!("{NATIVE} {PKT} --write-receipt {RCP}.bak"),
            format!("{NATIVE} /other/h.md --write-receipt {RCP}"),
            format!("{NATIVE} {PKT} --write-receipt /other/h.receipt.json"),
            // swapped roles
            format!("{NATIVE} {RCP} --write-receipt {PKT}"),
            // wrong flag
            format!("{NATIVE} {PKT} --verify-receipt {RCP}"),
            // self-check / authority bypass
            format!("{NATIVE} {PKT} --template-self-check"),
            format!("{NATIVE} {PKT} --template-self-check --write-receipt {RCP}"),
            format!("{NATIVE} {PKT} --write-receipt {RCP} --template-self-check"),
            // extra flag / chained commands / operators
            format!("{NATIVE} {PKT} --write-receipt {RCP} --verify-receipt {RCP}"),
            format!("{NATIVE} {PKT} --write-receipt {RCP}; rm -rf /"),
            format!("{NATIVE} {PKT} --write-receipt {RCP} && echo ok"),
            format!("echo ok && {NATIVE} {PKT} --write-receipt {RCP}"),
            format!("echo {NATIVE} {PKT} --write-receipt {RCP}"),
            // unterminated quote
            format!("{NATIVE} \"{PKT} --write-receipt {RCP}"),
        ];
        for cmd in bad {
            assert!(
                !command_binds_validator(&cmd, "--write-receipt", PKT, RCP),
                "must reject: {cmd}"
            );
        }
        // Empty declared paths can never be bound.
        let cmd = format!("{NATIVE} \"\" --write-receipt \"\"");
        assert!(!command_binds_validator(&cmd, "--write-receipt", "", ""));
    }

    #[test]
    fn verify_flag_is_enforced_for_receiver_check() {
        let verify = format!("{NATIVE} {PKT} --verify-receipt {RCP}");
        assert!(command_binds_validator(
            &verify,
            "--verify-receipt",
            PKT,
            RCP
        ));
        assert!(!command_binds_validator(
            &verify,
            "--write-receipt",
            PKT,
            RCP
        ));
    }

    #[test]
    fn strip_verbatim_prefix_handles_drive_unc_and_posix() {
        assert_eq!(strip_verbatim_prefix(r"\\?\C:\a\b.md"), r"C:\a\b.md");
        assert_eq!(
            strip_verbatim_prefix(r"\\?\UNC\srv\sh\b.md"),
            r"\\srv\sh\b.md"
        );
        assert_eq!(strip_verbatim_prefix("/a/b.md"), "/a/b.md");
        assert_eq!(strip_verbatim_prefix(r"C:\a\b.md"), r"C:\a\b.md");
    }

    #[test]
    fn existing_artifact_with_new_adjacent_receipt_passes() {
        let root = TestRoot::new("normal-new");
        let artifact = root.join("handoffs/h.md");
        let receipt = root.join("handoffs/h.receipt.json");
        write_file(&artifact, "body");
        assert!(!receipt.exists());
        let errors = check(&artifact, &receipt);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn existing_artifact_with_existing_receipt_passes() {
        let root = TestRoot::new("normal-existing");
        let artifact = root.join("handoffs/h.md");
        let receipt = root.join("handoffs/h.receipt.json");
        write_file(&artifact, "body");
        write_file(&receipt, "{}");
        let errors = check(&artifact, &receipt);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn verify_receipt_argument_is_checked_like_write_receipt() {
        let root = TestRoot::new("verify-arg");
        let artifact = root.join("handoffs/h.md");
        let receipt = root.join("handoffs/h.receipt.json");
        write_file(&artifact, "body");
        write_file(&receipt, "{}");
        let errors = storage_errors(
            &text_for(&artifact, &receipt),
            &artifact,
            None,
            Some(&receipt),
            WIN,
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn non_forbidden_alias_resolving_to_same_dir_passes_with_either_declared_spelling() {
        let root = TestRoot::new("alias-ok");
        write_file(&root.join("real/h.md"), "body");
        link_dir(&root.join("alias"), &root.join("real"));
        let artifact = root.join("alias/h.md");
        let receipt = root.join("alias/h.receipt.json");

        let lexical_declared = check(&artifact, &receipt);
        assert!(lexical_declared.is_empty(), "{lexical_declared:?}");

        let physical_artifact = root.join("real/h.md");
        let physical_receipt = root.join("real/h.receipt.json");
        let physical_declared = storage_errors(
            &text_for(&physical_artifact, &physical_receipt),
            &artifact,
            Some(&receipt),
            None,
            WIN,
        );
        assert!(physical_declared.is_empty(), "{physical_declared:?}");
    }

    #[test]
    fn symlink_into_forbidden_cache_storage_is_rejected() {
        let root = TestRoot::new("forbidden-link");
        write_file(&root.join("cache/real/h.md"), "body");
        link_dir(&root.join("stable"), &root.join("cache/real"));
        let artifact = root.join("stable/h.md");
        let receipt = root.join("stable/h.receipt.json");
        // Precondition: the supplied spelling looks clean; only the physical
        // location is forbidden.
        assert!(!lexical_has_forbidden(&artifact));
        assert!(!lexical_has_forbidden(&receipt));

        let errors = check(&artifact, &receipt);
        assert!(errors.iter().any(|e| e == FORBIDDEN_ARTIFACT), "{errors:?}");
        assert!(errors.iter().any(|e| e == FORBIDDEN_RECEIPT), "{errors:?}");
    }

    #[test]
    fn existing_receipt_symlinked_into_forbidden_storage_is_rejected() {
        let root = TestRoot::new("forbidden-receipt-dir");
        write_file(&root.join("ok/h.md"), "body");
        write_file(&root.join("scratch/h.receipt.json"), "{}");
        link_dir(&root.join("side"), &root.join("scratch"));
        let artifact = root.join("ok/h.md");
        let receipt = root.join("side/h.receipt.json");
        assert!(!lexical_has_forbidden(&receipt));

        let errors = check(&artifact, &receipt);
        assert!(errors.iter().any(|e| e == FORBIDDEN_RECEIPT), "{errors:?}");
        assert!(errors.iter().any(|e| e == NOT_ADJACENT), "{errors:?}");
    }

    #[test]
    fn lexically_forbidden_path_is_still_rejected() {
        let root = TestRoot::new("lexical-forbidden");
        let artifact = root.join("cache/h.md");
        let receipt = root.join("cache/h.receipt.json");
        write_file(&artifact, "body");
        let errors = check(&artifact, &receipt);
        assert!(errors.iter().any(|e| e == FORBIDDEN_ARTIFACT), "{errors:?}");
        assert!(errors.iter().any(|e| e == FORBIDDEN_RECEIPT), "{errors:?}");
    }

    #[test]
    fn missing_artifact_fails_closed_without_lexical_fallback() {
        let root = TestRoot::new("missing-artifact");
        let artifact = root.join("handoffs/h.md");
        let receipt = root.join("handoffs/h.receipt.json");
        // Lexically this would be a perfectly valid pair; it must still fail.
        let errors = check(&artifact, &receipt);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].starts_with("handoff path cannot be resolved to a physical location"),
            "{errors:?}"
        );
    }

    #[test]
    fn relative_artifact_is_rejected_as_not_absolute() {
        let errors = storage_errors(
            "- **Packet path:** `/x/h.md`\n- **Receipt path:** `/x/h.receipt.json`\n",
            Path::new("definitely-missing-l1b-relative/h.md"),
            Some(Path::new("/x/h.receipt.json")),
            None,
            false,
        );
        assert!(
            errors
                .iter()
                .any(|e| e == "validator requires absolute handoff file path"),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("cannot be resolved")),
            "{errors:?}"
        );
    }

    #[test]
    fn receipt_with_missing_parent_fails_closed() {
        let root = TestRoot::new("missing-receipt-parent");
        let artifact = root.join("handoffs/h.md");
        write_file(&artifact, "body");
        let receipt = root.join("handoffs/no-such-dir/h.receipt.json");
        let errors = check(&artifact, &receipt);
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with("receipt path cannot be resolved to a physical location")),
            "{errors:?}"
        );
    }

    #[test]
    fn receipt_without_basename_fails_closed() {
        let root = TestRoot::new("receipt-no-basename");
        write_file(&root.join("handoffs/h.md"), "body");
        // Lexical basename is checked before any filesystem call, so neither a
        // nonexistent-component `..` nor an existing-directory `..` (which some
        // platforms collapse to a directory during lookup) can slip through.
        for rel in ["handoffs/missing/..", "handoffs/.."] {
            let err = resolve_physical_receipt(&root.join(rel)).unwrap_err();
            assert!(err.contains("basename"), "{rel}: {err}");
        }
    }

    #[test]
    fn existing_directory_or_directory_link_receipt_is_rejected() {
        let root = TestRoot::new("receipt-is-directory");
        let artifact = root.join("handoffs/h.md");
        write_file(&artifact, "body");
        // A real directory named like the receipt.
        let dir_receipt = root.join("handoffs/h.receipt.json");
        std::fs::create_dir_all(&dir_receipt).unwrap();
        let err = resolve_physical_receipt(&dir_receipt).unwrap_err();
        assert!(err.contains("non-file target"), "{err}");
        let errors = check(&artifact, &dir_receipt);
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with("receipt path cannot be resolved to a physical location")),
            "{errors:?}"
        );

        // A directory link/junction whose basename looks like the receipt.
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        let link_receipt = root.join("handoffs/linked.receipt.json");
        link_dir(&link_receipt, &root.join("elsewhere"));
        let err = resolve_physical_receipt(&link_receipt).unwrap_err();
        assert!(err.contains("non-file target"), "{err}");
    }

    #[test]
    fn existing_regular_file_receipt_resolves_to_canonical_file() {
        let root = TestRoot::new("receipt-regular-file");
        let receipt = root.join("handoffs/h.receipt.json");
        write_file(&receipt, "{}");
        let physical = resolve_physical_receipt(&receipt).unwrap();
        // Expected value built component-wise so separators are native
        // (canonical Windows paths use backslashes; `join("a/b")` would not).
        let expected = root.0.join("handoffs").join("h.receipt.json");
        assert_eq!(
            physical_path_string(&physical),
            physical_path_string(&expected)
        );
    }

    #[cfg(unix)]
    #[test]
    fn dangling_receipt_symlink_fails_closed() {
        use super::test_support::link_file;
        let root = TestRoot::new("dangling-receipt");
        let artifact = root.join("handoffs/h.md");
        write_file(&artifact, "body");
        let receipt = root.join("handoffs/h.receipt.json");
        link_file(&receipt, &root.join("handoffs/does-not-exist.json"));
        let errors = check(&artifact, &receipt);
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with("receipt path cannot be resolved to a physical location")),
            "{errors:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dangling_artifact_symlink_fails_closed() {
        use super::test_support::link_file;
        let root = TestRoot::new("dangling-artifact");
        std::fs::create_dir_all(root.join("handoffs")).unwrap();
        let artifact = root.join("handoffs/h.md");
        link_file(&artifact, &root.join("handoffs/gone.md"));
        let errors = check(&artifact, &root.join("handoffs/h.receipt.json"));
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].starts_with("handoff path cannot be resolved"),
            "{errors:?}"
        );
    }

    #[test]
    fn receipt_in_different_directory_is_rejected_as_nonadjacent() {
        let root = TestRoot::new("plain-nonadjacent");
        let artifact = root.join("a/h.md");
        write_file(&artifact, "body");
        std::fs::create_dir_all(root.join("b")).unwrap();
        let errors = check(&artifact, &root.join("b/h.receipt.json"));
        assert!(errors.iter().any(|e| e == NOT_ADJACENT), "{errors:?}");
    }

    #[cfg(unix)]
    #[test]
    fn artifact_symlink_makes_lexically_adjacent_receipt_nonadjacent() {
        use super::test_support::link_file;
        let root = TestRoot::new("artifact-link-nonadjacent");
        write_file(&root.join("e/h.md"), "body");
        std::fs::create_dir_all(root.join("d")).unwrap();
        link_file(&root.join("d/h.md"), &root.join("e/h.md"));
        let artifact = root.join("d/h.md");
        let receipt = root.join("d/h.receipt.json");
        // Same lexical parent, different physical parent.
        assert_eq!(artifact.parent(), receipt.parent());

        let errors = check(&artifact, &receipt);
        assert!(errors.iter().any(|e| e == NOT_ADJACENT), "{errors:?}");
    }

    #[cfg(unix)]
    #[test]
    fn dotdot_through_link_is_resolved_physically_not_lexically() {
        let root = TestRoot::new("dotdot-link");
        write_file(&root.join("h.md"), "body");
        std::fs::create_dir_all(root.join("deep/x")).unwrap();
        link_dir(&root.join("link"), &root.join("deep/x"));
        // Lexically root/link/../h.receipt.json == root/h.receipt.json (adjacent);
        // physically it is root/deep/h.receipt.json.
        let artifact = root.join("h.md");
        let receipt = root.0.join("link").join("..").join("h.receipt.json");
        let errors = check(&artifact, &receipt);
        assert!(errors.iter().any(|e| e == NOT_ADJACENT), "{errors:?}");
    }

    #[test]
    fn receipt_basename_and_markdown_suffix_invariants_are_preserved() {
        let root = TestRoot::new("name-invariants");
        let artifact = root.join("handoffs/h.md");
        write_file(&artifact, "body");
        let errors = check(&artifact, &root.join("handoffs/other.receipt.json"));
        assert!(
            errors
                .iter()
                .any(|e| e == "handoff receipt must be named h.receipt.json"),
            "{errors:?}"
        );

        let txt = root.join("handoffs/h2.txt");
        write_file(&txt, "body");
        let errors = check(&txt, &root.join("handoffs/h2.receipt.json"));
        assert!(
            errors
                .iter()
                .any(|e| e == "canonical handoff must be Markdown"),
            "{errors:?}"
        );
    }

    #[test]
    fn declared_paths_that_match_neither_spelling_are_rejected() {
        let root = TestRoot::new("declared-mismatch");
        let artifact = root.join("handoffs/h.md");
        let receipt = root.join("handoffs/h.receipt.json");
        write_file(&artifact, "body");
        let text = text_for(
            &root.join("handoffs/other.md"),
            &root.join("handoffs/x.json"),
        );
        let errors = storage_errors(&text, &artifact, Some(&receipt), None, WIN);
        assert!(
            errors
                .iter()
                .any(|e| e == "declared handoff packet path does not match validated file"),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e == "declared receipt path does not match validator receipt argument"),
            "{errors:?}"
        );
    }

    #[test]
    fn missing_receipt_argument_is_reported() {
        let root = TestRoot::new("no-receipt-arg");
        let artifact = root.join("handoffs/h.md");
        write_file(&artifact, "body");
        let errors = storage_errors(
            &text_for(&artifact, &root.join("handoffs/h.receipt.json")),
            &artifact,
            None,
            None,
            WIN,
        );
        assert!(
            errors
                .iter()
                .any(|e| e == "validation must write or verify sidecar receipt"),
            "{errors:?}"
        );
    }
}
